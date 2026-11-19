package vercel

import (
	"bufio"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type outputConfig struct {
	Version int `json:"version"`
	Routes  []struct {
		Src    string `json:"src"`
		Dest   string `json:"dest"`
		Handle string `json:"handle"`
	} `json:"routes"`
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, value))
}

func commandNames(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../cmd/*/main.go")
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	names := make([]string, 0, len(paths))
	for _, path := range paths {
		names = append(names, filepath.Base(filepath.Dir(path)))
	}
	return names
}

func checkRoutes(t *testing.T, path string) {
	t.Helper()
	var config outputConfig
	readJSON(t, path, &config)
	require.Equal(t, 3, config.Version)

	redirects, err := os.Open("../_redirects")
	require.NoError(t, err)
	t.Cleanup(func() { _ = redirects.Close() })
	publicPaths := make(map[string]string)
	scanner := bufio.NewScanner(redirects)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		require.Len(t, fields, 3)
		require.Equal(t, "200!", fields[2])
		publicPaths[fields[0]] = strings.TrimPrefix(fields[1], "/.netlify/functions")
	}
	require.NoError(t, scanner.Err())
	require.Len(t, config.Routes, len(publicPaths)+1)
	require.Equal(t, "filesystem", config.Routes[len(config.Routes)-1].Handle)

	destinations := make([]string, 0, len(publicPaths))
	// Each exact path must target the same function as Netlify, without broad
	// catch-all routes or unescaped dots in well-known endpoint names.
	for _, route := range config.Routes {
		if route.Handle != "" {
			continue
		}
		found := false
		for publicPath, destination := range publicPaths {
			if route.Src == "^"+regexp.QuoteMeta(publicPath)+"$" {
				require.False(t, found)
				require.Equal(t, destination, route.Dest)
				found = true
			}
		}
		require.True(t, found, "unexpected route %s", route.Src)
		destinations = append(destinations, strings.TrimPrefix(route.Dest, "/"))
	}
	require.ElementsMatch(t, commandNames(t), destinations)
}

func TestRoutes(t *testing.T) {
	checkRoutes(t, "config.json")
}

// TestBuildOutput is explicitly enabled by make vercel-check; ordinary unit
// tests do not require large cross-compiled artifacts in the working tree.
func TestBuildOutput(t *testing.T) {
	output := os.Getenv("VERCEL_BUILD_OUTPUT")
	if output == "" {
		t.Skip("run make vercel vercel-check to validate compiled artifacts")
	}
	checkRoutes(t, filepath.Join(output, "config.json"))
	names := commandNames(t)
	entries, err := os.ReadDir(filepath.Join(output, "functions"))
	require.NoError(t, err)
	require.Len(t, entries, len(names), "missing or stale function bundles")
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			bundle := filepath.Join(output, "functions", name+".func")
			var config map[string]string
			readJSON(t, filepath.Join(bundle, ".vc-config.json"), &config)
			require.Equal(t, map[string]string{
				"runtime": "provided.al2023", "handler": "bootstrap", "architecture": "x86_64",
			}, config)
			binary := filepath.Join(bundle, config["handler"])
			info, err := os.Stat(binary)
			require.NoError(t, err)
			require.NotZero(t, info.Mode().Perm()&0111, "handler must be executable")
			file, err := elf.Open(binary)
			require.NoError(t, err)
			defer file.Close()
			require.Equal(t, elf.EM_X86_64, file.Machine)
			require.Equal(t, elf.ELFCLASS64, file.Class)
			for _, program := range file.Progs {
				require.NotEqual(t, elf.PT_INTERP, program.Type, "binary must not need a dynamic loader")
			}
			build, err := buildinfo.ReadFile(binary)
			require.NoError(t, err)
			settings := make(map[string]string)
			for _, setting := range build.Settings {
				settings[setting.Key] = setting.Value
			}
			require.Equal(t, "linux", settings["GOOS"])
			require.Equal(t, "amd64", settings["GOARCH"])
			require.Equal(t, "0", settings["CGO_ENABLED"])
			require.Contains(t, strings.Split(settings["-tags"], ","), "vercel")
		})
	}
	license, err := os.ReadFile("../LICENSE")
	require.NoError(t, err)
	staticLicense, err := os.ReadFile(filepath.Join(output, "static", "license.txt"))
	require.NoError(t, err)
	require.Equal(t, license, staticLicense)
	_, err = os.Stat(filepath.Join(output, "static", "_redirects"))
	require.True(t, os.IsNotExist(err), "Netlify routing must not be published as a static file")
}

// Exercise build ordering, incremental rebuilds, and cleanup with a small fake
// compiler so these regressions can be checked without cross-compiling twice.
func TestMakeLifecycle(t *testing.T) {
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Skip("make is not installed")
	}
	root := t.TempDir()
	write := func(path string, contents []byte, mode os.FileMode) {
		t.Helper()
		path = filepath.Join(root, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, contents, mode))
	}
	for _, path := range []string{"Makefile", "LICENSE", "_redirects", "vercel/config.json"} {
		contents, err := os.ReadFile(filepath.Join("..", path))
		require.NoError(t, err)
		write(path, contents, 0644)
	}
	for _, name := range commandNames(t) {
		write("cmd/"+name+"/main.go", []byte("package main\n"), 0644)
	}
	write("bin/go", []byte(`#!/bin/sh
set -eu
printf '%s\n' "$GOOS $GOARCH $CGO_ENABLED $*" >> builds.log
while [ "$#" -gt 0 ]; do
  if [ "$1" = '-o' ]; then
    shift
    printf 'fake binary\n' > "$1"
    chmod +x "$1"
    exit 0
  fi
  shift
done
exit 1
`), 0755)
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	// Do not inherit a recursive make invocation's jobserver or command overrides.
	t.Setenv("MAKEFLAGS", "")
	t.Setenv("MAKEOVERRIDES", "")
	run := func(target string) {
		t.Helper()
		cmd := exec.Command(makePath, "-j4", target)
		cmd.Dir = root
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	run("all")
	write(".vercel/project.json", []byte("keep project settings"), 0644)
	run("vercel")
	write(".vercel/output/functions/obsolete.func/bootstrap", []byte("stale"), 0755)
	write("internal/shared.go", []byte("changed imported source"), 0644)
	run("vercel")
	_, err = os.Stat(filepath.Join(root, ".vercel/output/functions/obsolete.func"))
	require.True(t, os.IsNotExist(err), "obsolete bundles must be removed")
	log, err := os.ReadFile(filepath.Join(root, "builds.log"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(log)), "\n")
	require.Len(t, lines, len(commandNames(t))*3, "all commands must rebuild after shared-source changes")
	for _, line := range lines {
		require.True(t, strings.HasPrefix(line, "linux amd64 0 build "), line)
	}
	run("clean-vercel")
	for _, path := range []string{".vercel/project.json", "functions/index", "public/_redirects"} {
		_, err := os.Stat(filepath.Join(root, path))
		require.NoError(t, err, "%s must be preserved", path)
	}
	_, err = os.Stat(filepath.Join(root, ".vercel/output"))
	require.True(t, os.IsNotExist(err))
}
