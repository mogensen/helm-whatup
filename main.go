/*
Copyright The Helm Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unsafe"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/Masterminds/semver/v3"
	"github.com/gosuri/uitable"
	"github.com/mgutz/ansi"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"helm.sh/helm/v3/cmd/helm/require"
	"helm.sh/helm/v3/cmd/helm/search"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/cli/output"
	"helm.sh/helm/v3/pkg/helmpath"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/repo"
)

// repoHighlightColor is the highlighting color for the repository, in the "multiple-repositories-view", from which the release
// has been installed from.
var repoHighlightColor = ansi.Green
var deprecatedStrColor = ansi.LightRed

var settings = cli.New()
var index *search.Index

func main() {
	// get action config first
	actionConfig := new(action.Configuration)

	err := actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), os.Getenv("HELM_DRIVER"), debug)
	if err != nil {
		log.Fatalf("Error while initializing actionConfig: %s", err.Error())
	}

	// check if we should enable BETA features
	b := os.Getenv("HELM_WHATUP_BETA_FEATURES")
	if b == "" {
		b = "false"
	}

	enableBetaFeatures, err = strconv.ParseBool(b)
	if err != nil {
		log.Fatalf("Invalid value in 'HELM_WHATUP_BETA_FEATURES': %s", err.Error())
	}

	rootCmd := newOutdatedCmd(actionConfig, os.Stdout)
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("There was an error while executing the Command: %s", err.Error())
	}
}

var outdatedHelp = `This Command lists all releases which are outdated.

By default, the output is printed in a Table but you can change this behavior
with the '--output' Flag.


You can enable all BETA features by executing:
	export HELM_WHATUP_BETA_FEATURES=true
`

// warn prints a warning message.
func warn(str string, a ...interface{}) {
	s := str
	if !strings.HasSuffix(str, "\n") {
		s += "\n"
	}

	fmt.Fprintf(os.Stderr, "WARNING: "+s, a...)
}

var (
	ignoreNoRepo bool = false
	showVersion  bool = false

	gitCommit          string
	version            string
	ignoreDeprecations bool // ignoreDeprecations describes if Charts, which are marked as deprecated, shall be ignored.
	enableBetaFeatures bool // enableBetaFeatures describes if all beta features should be enabled by default.
	// colorizeInstalledChart indicates that the repository should be colorized from where the chart has been installed.
	colorizeInstalledChart bool
	onlySrcUpdates         bool // onlySrcUpdates describes if the user wants to see only updates from its source repository.
)

// printWarnings prints Warning if specific flags have been set.
func printWarnings(out io.Writer) {
	printed := false

	// warn the user that deprecated charts will be excluded
	if ignoreDeprecations {
		printed = true
		warn("Charts marked as deprecated will not be shown in the results.")
	}

	if printed {
		fmt.Fprintf(out, "\n\n")
	}
}

func newOutdatedCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	client := action.NewList(cfg)
	var outfmt output.Format

	cmd := &cobra.Command{
		Use:     "whatup",
		Short:   "list outdated releases",
		Long:    outdatedHelp,
		Aliases: []string{"od"},
		Args:    require.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// bind flags against environment variables
			return initializeViper(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// check for special flags such as '--version' where the application should exit after printing the information
			if checkSpecFlags() {
				return nil
			}

			// print warnings for special flags
			printWarnings(out)

			if client.AllNamespaces {
				if err := cfg.Init(settings.RESTClientGetter(), "", os.Getenv("HELM_DRIVER"), debug); err != nil {
					return err
				}
			}
			client.SetStateMask()

			releases, err := client.Run()
			if err != nil {
				return err
			}

			devel, err := cmd.Flags().GetBool("devel")
			if err != nil {
				return err
			}

			return outfmt.Write(out, newOutdatedListWriter(releases, cfg, out, devel))
		},
	}

	flags := cmd.Flags()

	flags.BoolVar(&colorizeInstalledChart, "color", enableBetaFeatures, "[BETA] colorize/highlight the repositories from where the chart has been installed")

	flags.BoolVar(&ignoreDeprecations, "ignore-deprecation", true, "ignore/skip charts which are marked as \"DEPRECATED\"")
	flags.BoolVar(&ignoreNoRepo, "ignore-repo", true, "ignore error if no repo for a chart is found")
	flags.Bool("devel", false, "use development versions (alpha, beta, and release candidate releases), too. Equivalent to version '>0.0.0-0'.")
	flags.BoolVarP(&client.Short, "short", "q", false, "output short (quiet) listing format")
	flags.BoolVarP(&client.ByDate, "date", "d", false, "sort by release date")
	flags.BoolVarP(&client.SortReverse, "reverse", "r", false, "reverse the sort order")
	flags.BoolVarP(&client.All, "all", "a", false, "show all releases, not just the ones marked deployed or failed")
	flags.BoolVar(&client.Uninstalled, "uninstalled", false, "show uninstalled releases")
	flags.BoolVar(&client.Superseded, "superseded", false, "show superseded releases")
	flags.BoolVar(&client.Uninstalling, "uninstalling", false, "show releases that are currently being uninstalled")
	flags.BoolVar(&client.Deployed, "deployed", false, "show deployed releases. If no other is specified, this will be automatically enabled")
	flags.BoolVar(&client.Failed, "failed", false, "show failed releases")
	flags.BoolVar(&client.Pending, "pending", false, "show pending releases")
	flags.BoolVarP(&client.AllNamespaces, "all-namespaces", "A", false, "list releases across all namespaces")
	flags.IntVarP(&client.Limit, "max", "m", 256, "maximum number of releases to fetch")
	flags.IntVar(&client.Offset, "offset", 0, "next release name in the list, used to offset from start value")
	flags.BoolVar(&showVersion, "version", false, "show version information")
	flags.BoolVar(&onlySrcUpdates, "only-source-updates", true,
		"only show updates of a chart repository where the Chart-Version and App-Version do match.")

	bindOutputFlag(cmd, &outfmt)

	return cmd
}

// checkSpecFlags will check if a special flag was set where the application
// is not indented to work; it should only print some information.
//
// It will return 'true' if such a flag was detected.
func checkSpecFlags() bool {
	if showVersion {
		printVersion()
		return true
	}

	return false
}

// initializeViper initializes the viper (flag environment variable binding)
func initializeViper(cmd *cobra.Command) error {
	// NOTE: I wasn't able to get the 'automatic environment variable mapping' working so I do it manually

	// `ignore-repo`
	if str := os.Getenv("HELM_WHATUP_IGNORE_REPO"); str != "" {
		if _, err := strconv.ParseBool(str); err == nil {
			if err := cmd.Flags().Set("ignore-repo", str); err != nil {
				log.Fatalf("Error while parsing 'HELM_WHATUP_IGNORE_REPO' environment variable: %s", err.Error())
			}
		}
	}

	// `deprecation-notice`
	if str := os.Getenv("HELM_WHATUP_DEPRECATION_NOTICE"); str != "" {
		if _, err := strconv.ParseBool(str); err == nil {
			if err := cmd.Flags().Set("deprecation-notice", str); err != nil {
				log.Fatalf("Error while parsing 'HELM_WHATUP_DEPRECATION_NOTICE' environment variable: %s", err.Error())
			}
		}
	}

	return nil
}

type outdatedElement struct {
	Name         string    `json:"name"`
	Namespace    string    `json:"namespace"`
	InstalledVer string    `json:"installed_version"`
	LatestVer    string    `json:"latest_version"`
	AppVer       string    `json:"app_version"` // AppVer does contain the App version defined in 'Chart.yaml'
	Chart        string    `json:"chart"`
	NewestRepo   string    `json:"newest_repo,omitempty"` // NewestRepo contains the name of the repository with the updated Chart.
	Updated      time.Time `json:"updated"`               // Updated is the date the chart was updated.
	Deprecated   bool      `json:"deprecated"`            // Deprecated does contain `deprecated` field from the Chart.yaml file
}

type repoDuplicate struct {
	Name                  string            `json:"deploy_name"` // Name contains the deployment name
	Namespace             string            `json:"namespace"`   // Namespace contains the deployment namespace
	InstalledChartVersion string            `json:"installed_chart_version"`
	InstalledAppVersion   string            `json:"installed_app_version"`
	Repos                 []outdatedElement `json:"repos"` // Repos contains all the repositories which do serve this chart
	// IndexSrcRepo contains the position of the repository where the release (chart) has been installed from.
	// -1 indicates that no repo has been found from where the release chart has been downloaded.
	IndexSrcRepo int `json:"index_src_repo"`
}

type outdatedListWriter struct {
	Releases       []outdatedElement `json:"releases" yaml:"releases"`
	RepoDuplicates []repoDuplicate   `json:"repo_duplicates" yaml:"repo_duplicates"`
}

type searchType uint8

const (
	CHART searchType = iota + 1 // CHART search results do contain only one repository which has been found
	REPOS                       // REPOS search results do contain multiple repository which do serve the requested chart
)

// searchResult describes the result which has been found while searching a repository which does serve the requested chart
type searchResult struct {
	Type searchType

	chart *search.Result // chart will contain information about the (newer) chart if @Type is @CHART
	repos repoDuplicate  // repos will contain information if @Type is @REPOS
}

func newOutdatedListWriter(releases []*release.Release, cfg *action.Configuration, out io.Writer, devel bool) *outdatedListWriter {
	var err error

	outdated := make([]outdatedElement, 0, len(releases))
	dups := make([]repoDuplicate, 0, len(releases))

	// we initialize the Struct with default Options but the 'devel' option can be set by the User, all the other ones are not
	// relevant.
	searchRepo := searchRepoOptions{
		versions:     true, // index all versions
		regexp:       false,
		devel:        devel,
		maxColWidth:  50,
		version:      "",
		repoFile:     settings.RepositoryConfig,
		repoCacheDir: settings.RepositoryCache,
	}

	// initialize Repo index first
	index, err = initSearch(out, &searchRepo)
	if err != nil {
		// TODO: Find a better way to exit
		fmt.Fprintf(out, "%s", errors.Wrap(err, "ERROR: Could not initialize search index").Error())
		os.Exit(1)
	}

	var results []*search.Result

	// only index all repositories, if the source repository shall not be respected
	if !onlySrcUpdates {
		// get all locally indexed charts
		results = index.All()
	}

	for _, r := range releases {
		if onlySrcUpdates {
			results = index.SearchLiteral(r.Chart.Name(), 50)

			// find the source repository
			srcRepo := getSrcRepo(results, r.Chart.Name(), r.Chart.Metadata.Version, r.Chart.AppVersion())
			if srcRepo == "" {
				warn("The source repository could not be determined for '%s'", r.Name)
				continue
			}

			// only index versions of the source repository
			results = index.SearchLiteral(srcRepo+"/"+r.Chart.Name(), 50)
		}

		// search if it exists a newer Chart in the Chart-Repository
		repoResult, dep, err := searchChart(results, r, devel)
		if err != nil {
			if !ignoreNoRepo {
				fmt.Fprintf(out, "%s", errors.Wrap(err, "ERROR: Could not initialize search index").Error())
				os.Exit(1)
			} else {
				warn("No Repo was found which contains the Chart '%s' (skipping)\n", r.Chart.Name())
				continue
			}
		}

		// skip if no newer Chart was found
		if !dep {
			continue
		}

		if repoResult.Type == CHART {
			// skip if `ignore-deprecated` flag is true and the chart is deprecated
			if ignoreDeprecations && repoResult.chart.Chart.Deprecated {
				continue
			}

			outdated = append(outdated, outdatedElement{
				Name:         r.Name,
				Namespace:    r.Namespace,
				InstalledVer: r.Chart.Metadata.Version,
				LatestVer:    repoResult.chart.Chart.Metadata.Version,
				Chart:        repoResult.chart.Chart.Name,
				NewestRepo:   strings.Split(repoResult.chart.Name, "/")[0],
			})
		} else {
			repoResult.repos.Namespace = r.Namespace
			dups = append(dups, repoResult.repos)
		}
	}

	return &outdatedListWriter{
		Releases:       outdated,
		RepoDuplicates: dups,
	}
}

func initSearch(out io.Writer, o *searchRepoOptions) (*search.Index, error) {
	index, err := o.buildIndex(out)
	if err != nil {
		return nil, err
	}

	return index, nil
}

// searchChart searches for Repositories which are containing that chart.
// @name does contain the (deployed) chart named.
//
// It will return a struct with all search information.
// If no results are found, nil will be returned instead of type *Result.
// And the bool describes if it may be some Repositories contain a deprecated chart.
func searchChart(r []*search.Result, release *release.Release, devel bool) (searchResult, bool, error) {
	ret := searchResult{}

	// trackedRepos keeps information about a repository we already tracked.
	type trackedRepos struct {
		version    *semver.Version
		result     **search.Result // result is a reference to the data stored in chartRepos
		deprecated bool            // deprecated is true if the version of the chart is marked as deprecated.
	}

	// since we have now to check also if a repository contains an
	// deprecated chart we need an "point" where to look if we have found
	// a newer chart version
	foundNewer := false
	found := false                  // found describes if Charts where found but no one is newer than the actual one
	var chartRepos []*search.Result // chartRepos contains all repositories which serve the searched chart

	// repo tracks all chart repositories by its name, as key.
	repo := make(map[string]trackedRepos, len(r))

	// prepare the constrain string so we do not have the re-calculate it every time
	constrainStr := "> " + release.Chart.Metadata.Version
	if devel {
		constrainStr += "-0" + " != " + release.Chart.Metadata.Version
	}

	// TODO: implement a better search algorithm. Because this is an linear search algorithm so it takes O(len(r)) steps in the
	// worst case
	for i, result := range r {
		// check if the Chart-Result Name is that one we are searching for.
		if !strings.HasSuffix(strings.ToLower(result.Name), strings.ToLower(release.Chart.Name())) {
			continue
		}

		// check if Version is newer than the actual one
		version, err := semver.NewVersion(result.Chart.Metadata.Version)
		if err != nil {
			return ret, false, err
		}

		// store information that chart is deprecated
		if result.Chart.Deprecated {
			debug("Chart '%s' with version '%s' has been marked as DEPRECATED", result.Name, result.Chart.Metadata.Version)

			v, ok := repo[result.Name]
			if ok {
				// only change the deprecated state if the current Chart version is greater than the tracked one
				if version.GreaterThan(v.version) {
					// mark the tracked chart as deprecated so we can skip it later.
					v.deprecated = true
					repo[result.Name] = v
				}
			} else {
				// first time we track this repository
				debug("Tracking DEPRECATED chart '%s@%s' the first time [chartRepos]", result.Name, result.Chart.Version)
				chartRepos = append(chartRepos, result)

				resultVersion, err := semver.NewVersion(result.Chart.Version)
				if err != nil {
					return ret, false, err
				}

				repo[result.Name] = trackedRepos{
					version:    resultVersion,
					result:     &(r[i]), // store the address of the element, so we can change it later
					deprecated: true,
				}
			}

			// skip if chart is deprecated and 'ignore-deprecations' is enabled
			if ignoreDeprecations {
				continue
			}
		}

		constrain, err := semver.NewConstraint(constrainStr)
		if err != nil {
			return ret, false, err
		}

		debug("Comparing version of original chart '%s' => %s with version (%s) %s [constrain: '%s']",
			release.Chart.Name(), release.Chart.Metadata.Version, result.Name, result.Chart.Metadata.Version, constrainStr)
		if constrain.Check(version) {
			debug("Found newer version '%s' %s > %s", result.Name, result.Chart.Metadata.Version, result.Chart.Metadata.Version)
			foundNewer = true

			ver, ok := repo[result.Name]
			if !ok {
				// first time we track this repository
				chartRepos = append(chartRepos, result)

				resultVersion, err := semver.NewVersion(result.Chart.Version)
				if err != nil {
					return ret, false, err
				}

				repo[result.Name] = trackedRepos{
					version: resultVersion,
					result:  &(r[i]), // store the address of the element, so we can change it later
				}
			}

			// we already tracked a chart (version) from this repository so we have to change it
			if ok && ver.version.LessThan(version) {
				// change the tracked repository (*result) in the `chartRepos` array
				// ==> track only the newest version
				**ver.result = *result
				ver.version = version
				ver.deprecated = result.Chart.Deprecated

				repo[result.Name] = ver
			}
		}

		// // TODO(l0nax): refactor me ==> @duplicate append MUST be moved out of this if-block! */
		// if deprecationInfo {
		//     // add this Repository to the @duplicate variable, even if the version is not newer than the current installed.
		//     // This is because if the chart was installed at the time where the repository stopped maintaining the Chart we
		//     // would not know it – later – that this Repo is deperecated.
		//     chartRepos = append(chartRepos, result)
		// }

		// set 'found' to true because a Repository contains the Chart but the Version is not newer than the installed one.
		found = true
	}

	if !found {
		debug("Could not find any Repo which contains %s", release.Chart.Name())
		return ret, false, errors.New(fmt.Sprintf("Could not find any Repo which contains %s", release.Chart.Name()))
	}

	// check if we have multiple repositories which do serve the chart
	if len(chartRepos) > 1 {
		// NOTE: there is a special case when multiple repositories do serve this chart
		//       but one or more marked the chart as "deprecated", i.e. as done with all charts in the "stable" repository.
		repos := []outdatedElement{}
		crI := -1 // crI is the index in chartRepos

		for i, c := range chartRepos {
			if ignoreDeprecations {
				// the repo is tracked if not then we have BUG.
				if v := repo[c.Name]; v.deprecated {
					debug("Chart '%s@%s' is (internally) tracked as DEPRECATED and will be ignored for the future repos processing",
						c.Name, c.Chart.Metadata.Version)

					// chart has been marked as deprecated and user
					// don't wants to see deprecated charts => skip it
					continue
				}
			}

			repos = append(repos, outdatedElement{
				Name:         release.Chart.Name(),
				InstalledVer: release.Chart.Metadata.Version,
				AppVer:       c.Chart.Metadata.AppVersion,
				LatestVer:    c.Chart.Metadata.Version,
				Chart:        c.Name,
				Updated:      c.Chart.Created,
				Deprecated:   c.Chart.Deprecated,
			})

			crI = i
		}

		// as described in the first NOTE: it could be that multiple repos serve the chart but they marked it as deprecated.
		// In this case we may have only ONE repository left serving the chart.
		if len(repos) == 1 {
			debug("Only one repo does serve a non-deprecated chart for '%s'.", release.Chart.Name())

			// override the chart at index #0
			chartRepos[0] = chartRepos[crI]

			goto oneRepo
		} else if len(repos) == 0 { // special case: no repo has been found with the matching inputs
			debug("All found repositories serving '%s' have been filtered out. [foundNewer = false]", release.Chart.Name())
			foundNewer = false

			goto oneRepo
		}

		debug("%d repositories do serve the '%s' chart. Switching to 'REPOS' type.", len(chartRepos), release.Chart.Name())

		ret.Type = REPOS
		ret.repos = repoDuplicate{
			Name:                  release.Chart.Name(),
			Repos:                 repos,
			IndexSrcRepo:          -1,
			InstalledAppVersion:   release.Chart.AppVersion(),
			InstalledChartVersion: release.Chart.Metadata.Version,
		}

		if colorizeInstalledChart {
			// search the repository from where the release chart has been downloaded
			searchSrcRepo(&ret.repos)
		}

		return ret, true, nil
	}

oneRepo:
	// directly return if we haven't found a newer chart.
	if !foundNewer {
		debug("No newer Chart was found for '%s'", release.Chart.Name())
		return ret, false, nil
	}

	// check if the chart is deprecated.
	v := repo[chartRepos[0].Name]

	if v.deprecated && ignoreDeprecations {
		warn("The newest version for the chart '%s' is marked as "+
			deprecatedStrColor+"DEPRECATED"+ansi.Reset+"!", chartRepos[0].Name)
		return ret, false, nil
	}

	ret.Type = CHART
	ret.chart = chartRepos[0]

	// TODO(l0nax): Correct me
	return ret, true, nil
}

// getSrcRepo works like searchSrcRepo but it uses a search result i as search point.
//
// The data in i MUST be filtered before.
// Example:
//	i := index.SearchRegexp(".*/" + release.Chart.Name() + "$", 50)
//
// Where release.Chart.Name() is only the chart name WITHOUT the repositories name.
//
// The name of the source repo will be returned.
// The string will be empty if no source repo was found.
func getSrcRepo(i []*search.Result, chartName, chartVer, appVer string) string {
	for _, r := range i {
		if !strings.HasSuffix(r.Name, chartName) {
			// this could be if, i.e., there exists a HA version.
			// Installed chart named: postres
			// Charts returned from index search:
			//	- postgres
			//  - postgres-ha
			continue
		}

		// check Chart and App version
		if r.Chart.Version == chartVer && r.Chart.AppVersion == appVer {
			return strings.Split(r.Name, "/")[0]
		}
	}

	return ""
}

// searchSrcRepo searches in rs the repository from where the release chart has been downloaded.
// The index/position of the repoDuplicate.Repos array where the source repository resides
// will be stored in repoDuplicate.indexSrcRepo.
func searchSrcRepo(rd *repoDuplicate) {
	// NOTE: r.Chart does contain the FULL chart path, i.e. <REPOSITORY>/<CHART>

	for i, r := range rd.Repos {
		rs, err := index.Search(r.Chart, 50, false)
		if err != nil {
			log.Fatalf("An error occurred while searching for the source repository: %#+v\n", err)
		}

		// we need to know all previous versions of this chart
		v, err := getAllVersions(&r, rs)
		if err != nil {
			log.Fatalf("An error occurred while searching for the source repository: %#+v\n", err)
		}

		// check if this repo does have the EXACT same Chart-Version <=> App-Version
		app, ok := v[rd.InstalledChartVersion]
		if ok && app == rd.InstalledAppVersion {
			// we may be have found the repository which has been used to install this chart
			rd.IndexSrcRepo = i

			return
		}
	}
}

// getAllVersions returns all chart and app versions of r.
//
// The returned map is structured as follows:
//	- key..: Chart version
//	- value: App version
//
// If an error occurs, it will be returned.
func getAllVersions(r *outdatedElement, rs []*search.Result) (map[string]string, error) {
	ver := make(map[string]string, 50)

	for _, res := range rs {
		if res.Name != r.Chart {
			continue
		}

		ver[res.Chart.Version] = res.Chart.AppVersion
	}

	return ver, nil
}

func (r *outdatedListWriter) WriteTable(out io.Writer) error {
	table := uitable.New()

	table.AddRow("NAME", "NAMESPACE", "INSTALLED VERSION", "LATEST VERSION", "CHART", "REPOSITORY")
	for _, r := range r.Releases {
		table.AddRow(r.Name, r.Namespace, r.InstalledVer, r.LatestVer, r.Chart, r.NewestRepo)
	}

	// write basic table and then add additional information if we found multiple repositories which do serve one (or more)
	// deployed chart(s)
	err := output.EncodeTable(out, table)
	if err != nil {
		return err
	}

	if len(r.RepoDuplicates) == 0 {
		return nil
	}

	// print detailed information about "duplicated" repos
	fmt.Fprintf(out, "\n\n")

	// sepLen is the number of the seperator characters.
	// It does represent the terminal/tty width OR defaults to 90
	sepLen := int(terminalWidth())
	sep := genStr("-", sepLen)

	for _, dc := range r.RepoDuplicates {
		fmt.Fprintf(out, "\n%s\n", sep)

		// first print basic information about current deployment
		fmt.Fprintf(out, "%-27s%s\n", "NAME", dc.Name)
		fmt.Fprintf(out, "%-27s%s\n", "NAMESPACE", dc.Namespace)
		fmt.Fprintf(out, "%-27s%s\n", "INSTALLED CHART VERSION", dc.InstalledChartVersion)
		fmt.Fprintf(out, "%-27s%s\n\n", "INSTALLED APP VERSION", dc.InstalledAppVersion)

		// print repository table
		table = uitable.New()

		table.AddRow("REPOSITORY", "DEPRECATED", "CHART VERSION", "APP VERSION", "UPDATED")
		for iRepo, r := range dc.Repos {
			repo := strings.Split(r.Chart, "/")[0]

			// highlight the repo if it's the source repo
			if colorizeInstalledChart && iRepo == dc.IndexSrcRepo {
				repo = repoHighlightColor + repo + ansi.Reset
			}

			table.AddRow(repo, r.Deprecated, r.LatestVer, r.AppVer, r.Updated.UTC().String())
		}

		err := output.EncodeTable(out, table)
		if err != nil {
			return err
		}
	}

	return err
}

func (r *outdatedListWriter) WriteJSON(out io.Writer) error {
	return output.EncodeJSON(out, r)
}

func (r *outdatedListWriter) WriteYAML(out io.Writer) error {
	return output.EncodeYAML(out, r)
}

// terminalWidth returns the width of the current terminal OR 90 if the width could not be determined.
//
// Source: https://github.com/wayneashleyberry/terminal-dimensions/blob/c5d4738bc7c94ffd4c9b0ff4c248ce3aca664df5/terminaldimensions.go
func terminalWidth() uint {
	const defaultWidth = 90

	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return defaultWidth
	}

	_, width, err := parseTerminalWidth(bytes2string(out))
	if err != nil {
		return defaultWidth
	}

	return width
}

// parseTerminalWidth parses the output of `stty size` and returns Height and Width.
//
// Source: https://github.com/wayneashleyberry/terminal-dimensions/blob/c5d4738bc7c94ffd4c9b0ff4c248ce3aca664df5/terminaldimensions.go
func parseTerminalWidth(input string) (uint, uint, error) {
	parts := strings.Split(input, " ")
	x, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}
	y, err := strconv.Atoi(strings.Replace(parts[1], "\n", "", 1))
	if err != nil {
		return 0, 0, err
	}
	return uint(x), uint(y), nil
}

// genStr appends s n times and returns the result.
func genStr(s string, n int) string {
	var res string

	for i := 0; i < n; i++ {
		res += s
	}

	return res
}

// string2bytes converts the given string to a byte slice without memory allocation.
//
// Note it may break if string and/or slice header will change in future go versions.
func string2bytes(s string) (b []byte) {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh := *(*reflect.StringHeader)(unsafe.Pointer(&s))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len

	return b
}

func bytes2string(bytes []byte) string {
	sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(&bytes))
	stringHeader := reflect.StringHeader{Data: sliceHeader.Data, Len: sliceHeader.Len}
	return *(*string)(unsafe.Pointer(&stringHeader))
}

/// ===== Internal required Functions ====== ///

// checkDeprecation checks if there are repositories which are serving deprecated charts.
//
// TODO(l0nax): Implement me
func checkDeprecation(res []*search.Result) {
}

func debug(format string, v ...interface{}) {
	if settings.Debug {
		format = fmt.Sprintf("[debug] %s\n", format)
		log.Output(2, fmt.Sprintf(format, v...))
	}
}

// NOTE: Copied from https://github.com/helm/helm/blob/c05d78915190775fa9a79d8ebc85f57398331266/cmd/helm/flags.go#L54
const outputFlag = "output"

// bindOutputFlag will add the output flag to the given command and bind the value to the given format pointer
func bindOutputFlag(cmd *cobra.Command, varRef *output.Format) {
	cmd.Flags().VarP(newOutputValue(output.Table, varRef), outputFlag, "o",
		fmt.Sprintf("prints the output in the specified format. Allowed values: %s", strings.Join(output.Formats(), ", ")))
	// Setup shell completion for the flag
	cmd.MarkFlagCustom(outputFlag, "__helm_output_options")
}

// NOTE: Copied from https://github.com/helm/helm/blob/c05d78915190775fa9a79d8ebc85f57398331266/cmd/helm/flags.go#L63
type outputValue output.Format

func newOutputValue(defaultValue output.Format, p *output.Format) *outputValue {
	*p = defaultValue
	return (*outputValue)(p)
}

// func getNamespace() string {
//         // we can (try?) to get the current Namespace from the kubeConfig
//         kube.GetConfig(settings, context string, namespace string)
//         restClient := settings.
// }

// NOTE: This is copied from https://github.com/helm/helm/blob/c05d78915190775fa9a79d8ebc85f57398331266/cmd/helm/search_repo.go#L62
type searchRepoOptions struct {
	versions     bool
	regexp       bool
	devel        bool
	version      string
	maxColWidth  uint
	repoFile     string
	repoCacheDir string
	outputFormat output.Format
}

// NOTE: This is copied from https://github.com/helm/helm/blob/c05d78915190775fa9a79d8ebc85f57398331266/cmd/helm/search_repo.go#L170
func (o *searchRepoOptions) buildIndex(out io.Writer) (*search.Index, error) {
	// Load the repositories.yaml
	rf, err := repo.LoadFile(o.repoFile)
	if isNotExist(err) || len(rf.Repositories) == 0 {
		return nil, errors.New("no repositories configured")
	}

	i := search.NewIndex()

	for _, re := range rf.Repositories {
		n := re.Name
		f := filepath.Join(o.repoCacheDir, helmpath.CacheIndexFile(n))

		ind, err := repo.LoadIndexFile(f)
		if err != nil {
			// TODO: should print to stderr
			warn("Repo %q is corrupt or missing. Try 'helm repo update'.", n)
			continue
		}

		i.AddRepo(n, ind, o.versions || len(o.version) > 0)
	}

	return i, nil
}

// NOTE: This is copied from https://github.com/helm/helm/blob/c05d78915190775fa9a79d8ebc85f57398331266/cmd/helm/repo.go#L52
func isNotExist(err error) bool {
	return os.IsNotExist(errors.Cause(err))
}

// NOTE: Copied from  https://github.com/helm/helm/blob/c05d78915190775fa9a79d8ebc85f57398331266/cmd/helm/flags.go#L68
func (o *outputValue) String() string {
	// It is much cleaner looking (and technically less allocations) to just convert to a string rather than type asserting to the
	// underlying output.Format
	return string(*o)
}

func (o *outputValue) Type() string {
	return "format"
}

func (o *outputValue) Set(s string) error {
	outfmt, err := output.ParseFormat(s)
	if err != nil {
		return err
	}
	*o = outputValue(outfmt)
	return nil
}

// printVersion will print version information about this plugin.
func printVersion() {
	fmt.Printf("Plugin version.............: %s\n", Version)
	fmt.Printf("helm.sh/helm/v3 pkg version: %s\n", HelmVersion)
}
