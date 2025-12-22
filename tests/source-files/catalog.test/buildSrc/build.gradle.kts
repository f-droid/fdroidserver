plugins {
    alias(libs.plugins.google.services)
    alias(libs.plugins.firebase.crashlytics)
    alias(projectLibs.plugins.firebase.crashlytics)
}

dependencies {
    implementation(libs.plugins.androidApplication.asLibraryDependency)
    "playImplementation"(libs.firebase.core)
}
