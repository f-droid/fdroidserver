import java.io.FileInputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.google.services)
    alias(libs.plugins.firebase.crashlytics)
    alias(libs.plugins.ksp)
}
android {
    namespace = "com.lolo.io.onelist"

    val versionPropsFile = file("../version.properties")
    var versionCodeCI: Int? = null
    if (versionPropsFile.canRead()) {
        val versionProps = Properties()
        versionProps.load(FileInputStream(versionPropsFile))
        val v = versionProps["VERSION_CODE"]
        versionCodeCI = (versionProps["VERSION_CODE"] as String).toInt()
    }


    defaultConfig {
        multiDexEnabled = true
        applicationId = "com.lolo.io.onelist"
        compileSdk = 34
        minSdk = 23
        targetSdk = 34
        versionCode = versionCodeCI ?: 19
        versionName = "1.4.2"
        vectorDrawables.useSupportLibrary = true
    }

    androidResources {
        generateLocaleConfig = true
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }


    ksp {
        arg("room.schemaLocation", "$projectDir/schemas")
    }

    buildTypes {
        getByName("debug") {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-DEBUG"
            resValue("string", "app_name", "1ListDev")
        }
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true

            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            resValue("string", "app_name", "1List")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

}
repositories {
    google()
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

dependencies {

    // android
    implementation(libs.androidx.core.splashscreen)
    implementation(libs.androidx.preference.ktx)
    implementation(libs.androidx.lifecycle.extensions)
    implementation(libs.androidx.legacy.support.v4)
    implementation(libs.androidx.appcompat)

    // android - design
    implementation(libs.constraint.layout)
    implementation(libs.androidx.recyclerview)
    implementation(libs.flexbox)
    implementation(libs.material)
    implementation(libs.androidx.swiperefreshlayout)

    // kotlin
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlin.stdlib.jdk7)

    // firebase
    implementation(libs.firebase.crashlytics)

    // koin di
    implementation(libs.koin.android)
    implementation(libs.koin.androidx.navigation)

    // room
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    // json
    implementation(libs.gson)

    // other libs
    implementation(libs.whatsnew)
    implementation(libs.storage)
    implementation(libs.advrecyclerview)
}
