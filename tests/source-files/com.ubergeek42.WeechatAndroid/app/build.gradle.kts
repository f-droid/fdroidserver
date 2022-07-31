import com.android.build.api.transform.*
import com.android.build.api.variant.VariantInfo
import com.android.utils.FileUtils
import org.gradle.internal.os.OperatingSystem
import org.aspectj.bridge.IMessage
import org.aspectj.bridge.MessageHandler
import org.aspectj.tools.ajc.Main

plugins {
    id("com.android.application")
    kotlin("android")
    kotlin("kapt")
}

dependencies {
    implementation(project(":cats"))
    implementation(project(":relay"))

    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.7.0")

    // these two are required for logging within the relay module. todo remove?
    implementation("org.slf4j:slf4j-api:1.7.36")
    implementation("com.noveogroup.android:android-logger:1.3.6")

    implementation("androidx.core:core-ktx:1.8.0")
    implementation("androidx.legacy:legacy-support-v4:1.0.0")
    implementation("androidx.annotation:annotation:1.3.0") // For @Nullable/@NonNull
    implementation("androidx.appcompat:appcompat:1.4.2")
    implementation("androidx.emoji2:emoji2:1.1.0")
    implementation("androidx.preference:preference-ktx:1.2.0")  // preference fragment & al
    implementation("androidx.legacy:legacy-preference-v14:1.0.0") // styling for the fragment
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.4.1")
    implementation("androidx.lifecycle:lifecycle-common-java8:2.4.1")
    implementation("androidx.sharetarget:sharetarget:1.2.0-rc01")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.6.2")

    implementation("com.github.bumptech.glide:glide:4.13.2")
    kapt("com.github.bumptech.glide:compiler:4.13.2")
    implementation("com.squareup.okhttp3:okhttp:4.10.0")

    val roomVersion = "2.4.2"
    implementation("androidx.room:room-runtime:$roomVersion")
    annotationProcessor("androidx.room:room-compiler:$roomVersion")
    kapt("androidx.room:room-compiler:$roomVersion")

    implementation("org.yaml:snakeyaml:1.30")

    implementation("org.bouncycastle:bcpkix-jdk15on:1.70")

    // needed for thread-safe date formatting as SimpleDateFormat isn"t thread-safe
    // the alternatives, including apache commons and threetenabp, seem to be much slower
    // todo perhaps replace with core library desugaring, if it"s fast
    implementation("net.danlew:android.joda:2.10.14")

    implementation("org.greenrobot:eventbus:3.3.1")

    debugImplementation("org.aspectj:aspectjrt:1.9.9.1")
    debugImplementation("com.squareup.leakcanary:leakcanary-android:2.9.1")

    testImplementation("org.junit.jupiter:junit-jupiter:5.8.2")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.8.2")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

android {
    compileSdk = 31

    defaultConfig {
        versionCode = 1_08_01
        versionName = "1.8.1"

        minSdk = 21
        targetSdk = 31
        buildConfigField("String", "VERSION_BANNER", "\"" + versionBanner() + "\"")

        vectorDrawables.useSupportLibrary = true

        javaCompileOptions {
            annotationProcessorOptions {
                arguments["room.schemaLocation"] = "$projectDir/schemas"
                arguments["room.incremental"] = "true"
            }
        }

        kotlinOptions {
            freeCompilerArgs = listOf(
                    "-language-version", "1.7",
                    "-api-version", "1.7")
            jvmTarget = "11"
        }
    }

    signingConfigs {
        create("dev") {
            try {
                storeFile = file(project.properties["devStorefile"] as String)
                storePassword = project.properties["devStorePassword"] as String
                keyAlias = project.properties["devKeyAlias"] as String
                keyPassword = project.properties["devKeyPassword"] as String
            } catch (e: Exception) {
                project.logger.warn("WARNING: Set the values devStorefile, devStorePassword, " +
                        "devKeyAlias, and devKeyPassword " +
                        "in ~/.gradle/gradle.properties to sign the release.")
            }
        }
    }

    buildTypes {
        getByName("debug") {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }

        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"),
                          "proguard-rules.pro",
                          "../cats/proguard-rules.pro")
            // kotlinx-coroutines-core debug-only artifact
            // see https://github.com/Kotlin/kotlinx.coroutines#avoiding-including-the-debug-infrastructure-in-the-resulting-apk
            packagingOptions {
                resources.excludes += "DebugProbesKt.bin"
            }
        }

        create("dev") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
            signingConfig = signingConfigs.getByName("dev")
        }

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_11
            targetCompatibility = JavaVersion.VERSION_11
        }
    }

    buildFeatures {
        viewBinding = true
    }
}

fun versionBanner(): String {
    val os = org.apache.commons.io.output.ByteArrayOutputStream()
    project.exec {
        commandLine = "git describe --long".split(" ")
        standardOutput = os
    }
    return String(os.toByteArray()).trim()
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////// cats
////////////////////////////////////////////////////////////////////////////////////////////////////

// ajc gets hold of some files such as R.jar, and on Windows it leads to errors such as:
//   The process cannot access the file because it is being used by another process
// to avoid these, weave in a process, which `javaexec` will helpfully launch for us.

fun weave(classPath: Iterable<File>, aspectPath: Iterable<File>, input: Iterable<File>, output: File) {
    val runInAProcess = OperatingSystem.current().isWindows
    val bootClassPath = android.bootClasspath

    println(if (runInAProcess) ":: weaving in a process..." else ":: weaving...")
    println(":: boot class path:  $bootClassPath")
    println(":: class path:       $classPath")
    println(":: aspect path:      $aspectPath")
    println(":: input:            $input")
    println(":: output:           $output")

    val arguments = listOf("-showWeaveInfo",
                           "-1.8",
                           "-preserveAllLocals",
                           "-bootclasspath", bootClassPath.asArgument,
                           "-classpath", classPath.asArgument,
                           "-aspectpath", aspectPath.asArgument,
                           "-inpath", input.asArgument,
                           "-d", output.absolutePath)

    if (runInAProcess) {
        javaexec {
            classpath = weaving
            main = "org.aspectj.tools.ajc.Main"
            args = arguments
        }
    } else {
        val handler = MessageHandler(true)
        Main().run(arguments.toTypedArray(), handler)

        val log = project.logger
        for (message in handler.getMessages(null, true)) {
            when (message.kind) {
                IMessage.DEBUG -> log.debug("DEBUG " + message.message, message.thrown)
                IMessage.INFO -> log.info("INFO: " + message.message, message.thrown)
                IMessage.WARNING -> log.warn("WARN: " + message.message, message.thrown)
                IMessage.FAIL,
                IMessage.ERROR,
                IMessage.ABORT -> log.error("ERROR: " + message.message, message.thrown)
            }
        }
    }
}

// the only purpose of the following is to get a hold of aspectjtools jar
// this jar is already on build script classpath, but that classpath is impossible to get
// see https://discuss.gradle.org/t/how-do-i-determine-buildscript-classpath/37973/3

val weaving: Configuration by configurations.creating

dependencies {
    weaving("org.aspectj:aspectjtools:1.9.9.1")
}

// historical note: the problem with weaving Kotlin and Java in-place is that:
//   * Java is compiled by task compileDebugJavaWithJavac
//   * gradle can run either one of these tasks, or both of them
//   * compileDebugJavaWithJavac depends on compileDebugKotlin
//   * weaving Kotlin requires Java classes
//
// a transformation is a poorly advertised feature that works on merged code, and also has its own
// inputs and outputs, so this fixes all of our problems...

    class TransformCats : Transform() {
    override fun getName(): String = TransformCats::class.simpleName!!

    override fun getInputTypes() = setOf(QualifiedContent.DefaultContentType.CLASSES)

    // only look for annotations in app classes
    // transformation will consume these and put woven classes in the output dir
    override fun getScopes() = mutableSetOf(QualifiedContent.Scope.PROJECT)

    // but also have the rest on our class path
    // these will not be touched by the transformation
    override fun getReferencedScopes() = mutableSetOf(QualifiedContent.Scope.SUB_PROJECTS,
                                                      QualifiedContent.Scope.EXTERNAL_LIBRARIES)

    override fun isIncremental() = false

    // only run on debug builds
    override fun applyToVariant(variant: VariantInfo) = variant.isDebuggable

    override fun transform(invocation: TransformInvocation) {
        if (!invocation.isIncremental) {
            invocation.outputProvider.deleteAll()
        }

        val output = invocation.outputProvider.getContentLocation(name, outputTypes,
                                                                  scopes, Format.DIRECTORY)
        if (output.isDirectory) FileUtils.deleteDirectoryContents(output)
        FileUtils.mkdirs(output)

        val input = mutableListOf<File>()
        val classPath = mutableListOf<File>()
        val aspectPath = mutableListOf<File>()

        invocation.inputs.forEach { source ->
            source.directoryInputs.forEach { dir ->
                input.add(dir.file)
                classPath.add(dir.file)
            }

            source.jarInputs.forEach { jar ->
                input.add(jar.file)
                classPath.add(jar.file)
            }
        }

        invocation.referencedInputs.forEach { source ->
            source.directoryInputs.forEach { dir ->
                classPath.add(dir.file)
            }

            source.jarInputs.forEach { jar ->
                classPath.add(jar.file)
                // this used to read `if (jar.name == ":cats") ...`,
                // but with android gradle plugin 4.2.0 jar names contain garbage
                // this is a very simple but a bit fragile workaround. todo improve
                if (jar.file.directoriesInsideRootProject().contains("cats")) {
                    aspectPath.add(jar.file)
                }
            }

        }

        weave(classPath, aspectPath, input, output)
    }
}

android.registerTransform(TransformCats())

val Iterable<File>.asArgument get() = joinToString(File.pathSeparator)

fun File.directoriesInsideRootProject() = sequence {
    var file = this@directoriesInsideRootProject
    while (true) {
        yield(file.name)
        file = file.parentFile ?: break
        if (file == rootProject.projectDir) break
    }
}
