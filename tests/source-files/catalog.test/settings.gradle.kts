dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
    defaultLibrariesExtensionName = "projectLibs"
    versionCatalogs {
        create("libs") {
            from(files("./libs.versions.toml"))
        }
        create("anotherLibs") {
            from(files("$rootDir/libs.versions.toml"))
        }
    }
}
