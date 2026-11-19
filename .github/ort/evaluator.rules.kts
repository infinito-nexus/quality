val allowed = java.io.File(System.getenv("ORT_ALLOWED_LICENSES")).readLines().map { it.trim() }.filter { it.isNotEmpty() }.toSet()

val ruleSet = ruleSet(ortResult, licenseInfoResolver, resolutionProvider) {
    packageRule("LICENSE_OUTSIDE_ALLOWLIST") {
        require {
            -isExcluded()
        }

        licenseRule("LICENSE_OUTSIDE_ALLOWLIST", LicenseView.CONCLUDED_OR_DECLARED_AND_DETECTED) {
            require {
                -isExcluded()
            }

            if (license.toString() !in allowed) {
                error(
                    "${pkg.metadata.id.toCoordinates()} carries $license, outside the allowlist of rules/legal.yml.",
                    "Replace the dependency, or widen the allowlist in .quality/legal.yml after a legal review."
                )
            }
        }
    }
}

ruleViolations += ruleSet.violations
