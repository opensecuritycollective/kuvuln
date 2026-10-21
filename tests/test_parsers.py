import unittest
from pathlib import Path

from kuvuln.config import Config
from kuvuln.parsers import (
    collect_dependencies,
    parse_dependency_file,
)

LOCKS = Path(__file__).parent / "fixtures" / "locks"
GO = Path(__file__).parent / "fixtures" / "go"


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.config = Config({})

    def parse(self, relative: str):
        return parse_dependency_file(LOCKS / relative, LOCKS, self.config)

    def parse_go(self, relative: str):
        return parse_dependency_file(GO / relative, GO, self.config)

    def test_package_lock_v3(self):
        deps = self.parse("package-lock.json").dependencies
        by_name = {dep.name: dep for dep in deps}
        self.assertEqual(by_name["lodash"].version, "4.17.20")
        self.assertEqual(by_name["lodash"].ecosystem, "npm")
        self.assertEqual(by_name["lodash"].license, "MIT")
        self.assertEqual(by_name["left-pad"].scope, "dev")

    def test_yarn_lock(self):
        deps = self.parse("yarn.lock").dependencies
        names = {dep.name: dep for dep in deps}
        self.assertIn("lodash", names)
        self.assertIn("@babel/code-frame", names)
        self.assertEqual(names["@babel/code-frame"].version, "7.24.7")

    def test_pnpm_lock(self):
        deps = self.parse("pnpm-lock.yaml").dependencies
        names = {dep.name: dep for dep in deps}
        self.assertEqual(names["lodash"].version, "4.17.20")
        self.assertEqual(names["express"].version, "4.21.0")
        self.assertEqual(names["@babel/code-frame"].version, "7.24.7")

    def test_requirements(self):
        deps = self.parse("requirements.txt").dependencies
        versions = {dep.name: dep.version for dep in deps}
        self.assertEqual(versions.get("requests"), "2.31.0")
        self.assertEqual(versions.get("boto3"), "1.35.0")
        self.assertNotIn("flask", versions)

    def test_poetry_lock(self):
        deps = self.parse("poetry.lock").dependencies
        by_name = {dep.name: dep for dep in deps}
        self.assertEqual(by_name["django"].version, "4.2.0")
        self.assertEqual(by_name["django"].scope, "runtime")
        self.assertEqual(by_name["pytest"].scope, "dev")

    def test_uv_lock(self):
        deps = self.parse("uv.lock").dependencies
        self.assertEqual(deps[0].name, "fastapi")
        self.assertEqual(deps[0].ecosystem, "PyPI")

    def test_pipfile_lock(self):
        deps = self.parse("Pipfile.lock").dependencies
        by_name = {dep.name: dep for dep in deps}
        self.assertEqual(by_name["requests"].version, "2.31.0")
        self.assertEqual(by_name["pytest"].scope, "dev")

    def test_cargo_lock(self):
        deps = self.parse("Cargo.lock").dependencies
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].name, "serde")
        self.assertEqual(deps[0].ecosystem, "crates.io")

    def test_maven_pom(self):
        deps = self.parse("pom.xml").dependencies
        names = {dep.name: dep for dep in deps}
        self.assertIn("org.apache.logging.log4j:log4j-core", names)
        self.assertEqual(names["org.springframework:spring-context"].scope, "dev")

    def test_composer_lock(self):
        deps = self.parse("composer.lock").dependencies
        by_name = {dep.name: dep for dep in deps}
        self.assertEqual(by_name["monolog/monolog"].version, "2.9.3")
        self.assertEqual(by_name["monolog/monolog"].license, "MIT")
        self.assertEqual(by_name["phpunit/phpunit"].scope, "dev")

    def test_gemfile_lock(self):
        deps = self.parse("Gemfile.lock").dependencies
        names = {dep.name: dep for dep in deps}
        self.assertEqual(names["rails"].version, "7.1.0")
        self.assertEqual(names["rake"].ecosystem, "RubyGems")

    def test_nuget_lock(self):
        deps = self.parse("packages.lock.json").dependencies
        versions = {dep.name: dep.version for dep in deps}
        self.assertEqual(versions["Newtonsoft.Json"], "13.0.3")
        self.assertEqual(versions["Serilog"], "4.0.0")

    def test_pubspec_lock(self):
        deps = self.parse("pubspec.lock").dependencies
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].name, "http")
        self.assertEqual(deps[0].version, "1.2.0")

    def test_mix_lock(self):
        deps = self.parse("mix.lock").dependencies
        names = {dep.name: dep for dep in deps}
        self.assertIn("phoenix", names)
        self.assertNotIn("local_dep", names)

    def test_gradle_lock(self):
        deps = self.parse("gradle.lockfile").dependencies
        self.assertEqual(deps[0].name, "org.springframework:spring-core")
        self.assertEqual(deps[0].version, "5.3.39")

    def test_package_json_exact_only(self):
        deps = self.parse("package.json").dependencies
        names = {dep.name: dep for dep in deps}
        self.assertIn("react", names)
        self.assertNotIn("lodash", names)
        self.assertEqual(names["vitest"].scope, "dev")

    def test_pyproject_exact(self):
        deps = self.parse("pyproject.toml").dependencies
        names = {dep.name: dep for dep in deps}
        self.assertIn("requests", names)
        self.assertIn("pytest", names)
        self.assertNotIn("flask", names)

    def test_go_mod_replacements(self):
        deps = self.parse_go("go.mod").dependencies
        by_name = {dep.name: dep for dep in deps}
        self.assertIn("github.com/gorilla/mux", by_name)
        self.assertIn("github.com/example/text-fork", by_name)
        self.assertNotIn("golang.org/x/text", by_name)
        self.assertEqual(by_name["github.com/example/text-fork"].version, "v0.4.0")
        self.assertTrue(by_name["github.com/pkg/errors"].properties["indirect"])

    def test_go_list_stream(self):
        deps = self.parse_go("gomodules.json").dependencies
        names = {dep.name: dep for dep in deps}
        self.assertEqual(names["github.com/gorilla/mux"].version, "v1.8.0")
        self.assertEqual(names["github.com/example/text-fork"].version, "v0.4.0")
        self.assertNotIn("github.com/example/demo", names)

    def test_vendor_modules(self):
        deps = self.parse_go("vendor/modules.txt").dependencies
        names = {dep.name: dep for dep in deps}
        self.assertIn("github.com/gorilla/mux", names)
        self.assertEqual(names["github.com/example/text-fork"].version, "v0.4.0")

    def test_collect_filters_ecosystems_and_dev(self):
        deps, _warnings = collect_dependencies([LOCKS, GO], self.config)
        self.assertTrue(deps)
        ecosystems = {dep.ecosystem for dep in deps}
        self.assertIn("Go", ecosystems)
        self.assertIn("npm", ecosystems)
        config = Config(
            {
                "sca": {
                    "ecosystems": ["Go"],
                    "include_dev": False,
                    "include_indirect": False,
                }
            }
        )
        filtered, _ = collect_dependencies([LOCKS, GO], config)
        self.assertTrue(all(dep.ecosystem == "Go" for dep in filtered))
        self.assertFalse(any(dep.scope == "dev" for dep in filtered))
        self.assertFalse(any(dep.properties.get("indirect") for dep in filtered))

    def test_exclusions_respected(self):
        config = Config({"settings": {"exclusions": {"directories": ["vendor/**"]}}})
        deps, _ = collect_dependencies([Path(__file__).parent / "fixtures" / "go"], config)
        self.assertTrue(all(dep.ecosystem == "Go" for dep in deps))


if __name__ == "__main__":
    unittest.main()
