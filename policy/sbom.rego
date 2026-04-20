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
# title: Disallowed license
# description: Confirm packages in SBOM do not contain any disallowed licenses.
# custom:
#   short_name: disallowed-license
#   failure_msg: "Package %q declares a disallowed license: %q"
deny contains result if {
	some pkg in input.packages
	regex.match(`\bGPL\b`, pkg.licenseDeclared)
	result := lib.result_helper(rego.metadata.chain(), [pkg.name, pkg.licenseDeclared])
}
