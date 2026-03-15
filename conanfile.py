import os
import re

from conan import ConanFile
from conan.errors import ConanException
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.scm import Git


class VanetzaConan(ConanFile):
    name = "vanetza"
    url = "https://github.com/riebl/vanetza"
    description = "Open-source implementation of the ETSI C-ITS protocol stack"
    license = "LGPL-3.0-or-later"
    package_type = "library"
    languages = "C", "C++"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "fPIC": [True, False],
        "shared": [True, False],
        "testing": [True, False],
        "with_cryptopp": [True, False],
        "with_openssl": [True, False],
        "build_socktap": [True, False],
        "build_certify": [True, False],
        "build_benchmark": [True, False],
    }
    default_options = {
        "fPIC": True,
        "shared": False,
        "testing": True,
        "with_cryptopp": False,
        "with_openssl": True,
        "build_socktap": False,
        "build_certify": False,
        "build_benchmark": False,
    }

    def read_project_version(self) -> str | None:
        version_re = re.compile(r"project\(Vanetza VERSION ([\d.]+)\)")
        with open(os.path.join(self.recipe_folder, "CMakeLists.txt")) as f:
            for line in f:
                match = version_re.search(line)
                if match:
                    return match.group(1)
        return None

    def set_version(self):
        project_version = self.read_project_version()
        if not project_version:
            raise ConanException("Could not read version from CMakeLists.txt")

        git = Git(self)
        try:
            count = int(git.run(f"rev-list --count v{project_version}..HEAD"))
            if count > 0:
                short_hash = git.run("rev-parse --short HEAD")
                self.version = f"{project_version}-dev+{count}.{short_hash}"
        except Exception:
            self.version = project_version

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self)

    def requirements(self):
        self.requires("boost/[>=1.70]")
        self.requires("geographiclib/[>=1.37]")
        if self.options.with_cryptopp:
            self.requires("cryptopp/[>=5.6.1]")
        if self.options.with_openssl:
            self.requires("openssl/[>=1.1 <4]")

    def validate(self):
        from conan.tools.build import check_min_cppstd

        check_min_cppstd(self, "14")

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["BUILD_SHARED_LIBS"] = self.options.shared
        tc.variables["BUILD_TESTS"] = self.options.testing
        tc.variables["VANETZA_WITH_CRYPTOPP"] = self.options.with_cryptopp
        tc.variables["VANETZA_WITH_OPENSSL"] = self.options.with_openssl
        tc.variables["BUILD_SOCKTAP"] = self.options.build_socktap
        tc.variables["BUILD_CERTIFY"] = self.options.build_certify
        tc.variables["BUILD_BENCHMARK"] = self.options.build_benchmark
        tc.generate()
        deps = CMakeDeps(self)
        deps.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        if self.options.testing:
            cmake.test()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        # ordered from dependents to dependencies for correct static linking
        self.cpp_info.libs = [
            "vanetza_facilities",
            "vanetza_btp",
            "vanetza_geonet",
            "vanetza_security",
            "vanetza_dcc",
            "vanetza_access",
            "vanetza_net",
            "vanetza_gnss",
            "vanetza_common",
            "vanetza_asn1",
            "vanetza_asn1_its",
            "vanetza_asn1_pki",
            "vanetza_asn1_security",
            "vanetza_asn1_support",
        ]
