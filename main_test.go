package main

import (
	"os"
	"testing"
)

// BenchmarkBuildIndex9 benchmarks the buildIndex() method with a 9MB big index.
func BenchmarkBuildIndex9(b *testing.B) {
	repoFile := "testdata/helmhome/helm/large/repositories.yaml"
	repoCache := "testdata/helmhome/helm/large/"

	searchRepo := searchRepoOptions{
		versions:     true, // load ALL charts from the index
		regexp:       false,
		devel:        true,
		maxColWidth:  50,
		version:      "",
		repoFile:     repoFile,
		repoCacheDir: repoCache,
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		index, err := searchRepo.buildIndex(os.Stderr)
		if err != nil {
			b.Fatal(err)
		}

		_ = index
	}
}
