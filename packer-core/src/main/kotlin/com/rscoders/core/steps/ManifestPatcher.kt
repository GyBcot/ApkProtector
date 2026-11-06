package com.rscoders.core.steps

import java.io.File

class ManifestPatcher {

    data class Patched(val originalApplicationClass: String?)

    private val appTagRegex = Regex("<application\\b[^>]*", RegexOption.DOT_MATCHES_ALL)
    private val nameAttrRegex = Regex("android:name\\s*=\\s*\"([^\"]*)\"")

    fun patch(manifest: File, stubClass: String): Patched {
        val text = manifest.readText()
        val appTag = appTagRegex.find(text)
            ?: error("No <application> tag found in ${manifest.path}")

        val original: String?
        val newAppTag: String

        val nameMatch = nameAttrRegex.find(appTag.value)
        if (nameMatch != null) {
            original = nameMatch.groupValues[1]
            newAppTag = appTag.value.replaceRange(
                nameMatch.range,
                "android:name=\"$stubClass\"",
            )
        } else {
            original = null
            newAppTag = appTag.value.replaceFirst(
                "<application",
                "<application android:name=\"$stubClass\"",
            )
        }

        val patched = text.replaceRange(appTag.range, newAppTag)
        manifest.writeText(patched)
        return Patched(original)
    }
}
