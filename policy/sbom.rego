#
# METADATA
# title: SBOM Licenses
# description: >-
#   Checks the licenses of packages in an SBOM.
#
package sbom

import rego.v1

import data.lib


# METADATA
# title: Found
# description: At least one SBOM has been found
# custom:
#   short_name: found
#   failure_msg: No SBOMs found
deny contains result if {
	count(_sboms) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Disallowed license
# description: Confirm packages in SBOM do not contain any disallowed licenses.
# custom:
#   short_name: disallowed-license
#   failure_msg: "Package %q declares a disallowed license: %q"
deny contains result if {
	some sbom in _sboms
	some pkg in sbom.packages
	regex.match(`\bGPL\b`, pkg.licenseDeclared)
	result := lib.result_helper_with_term(rego.metadata.chain(), [pkg.name, pkg.licenseDeclared], pkg.name)
}

_sboms contains input if {
	input.SPDXID == "SPDXRef-DOCUMENT"
}
