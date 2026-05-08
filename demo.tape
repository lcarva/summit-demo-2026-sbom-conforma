Output demo.mp4

Require cosign
Require ec
Require bat
Require jq
Require git

Set Shell "bash"
Set FontSize 18
Set Width 1400
Set Height 800
Set Padding 20
Set TypingSpeed 40ms

################
#### Setup #####
################

# Set the container image
Type@5ms "IMAGE='registry.access.redhat.com/hi/nodejs@sha256:800a2372b211b98caa6b390b40224854022c8a29c8e81ffc2a090c2e4156d852'"
Enter

# Download the SBOM for the image
Type "cosign download sbom $IMAGE > sbom.json 2> /dev/null"
Enter
Wait

# Show some parts of the SBOM
Type "jq -r '.packages | length' sbom.json | sort -u | head"
Enter
Type "jq -r '.packages[].licenseDeclared' sbom.json | sort -u | head"
Enter
Sleep 3s

########################
#### Show Policies #####
########################

Hide
Type "clear"
Enter
Show

Hide
# Go to the first commit in the repo
Type@5ms "git checkout $(git rev-list --all main | tail -n 1)"
Enter
Show

# Show the policy files
Type "bat policy/sbom.rego"
Enter
Sleep 3s
Type "bat policy.yaml"
Enter
Sleep 3s

########################
########### Run EC #####
########################

Hide
Type "clear"
Enter
Show

Type "# Run validation - this should fail due to disallowed licenses"
Enter
Type "ec validate input --file sbom.json --policy policy.yaml"
Enter
Wait
Sleep 3s

########################
##### Less Opaque ######
########################

Hide
Type "clear"
Enter
Show

Type "# Make the error less opaque"
Enter

Hide
# Go to the next commit - adds package and license details to violations
Type@5ms "git checkout $(git rev-list --ancestry-path HEAD..main --reverse | head -n 1)"
Enter
Show

# Show what changed
Type "git --no-pager show HEAD"
Enter
Sleep 3s

Type "# Run validation again - now we can see which packages and licenses failed"
Enter
Type "ec validate input --file sbom.json --policy policy.yaml"
Enter
Wait
Sleep 3s

########################
###### Add Term ########
########################

Hide
Type "clear"
Enter
Show

Hide
# Go to the next commit - adds a "term" for fine-grained exclusion
Type@5ms "git checkout $(git rev-list --ancestry-path HEAD..main --reverse | head -n 1)"
Enter
Show

# Show what changed
Type "git --no-pager show HEAD"
Enter
Sleep 3s

Type "# Run validation - violation for the sed package is no longer there"
Enter
Type "ec validate input --file sbom.json --policy policy.yaml"
Enter
Wait
Sleep 3s

Hide
Type "clear"
Enter
Show

Type "# What happens with a JSON that is not an SBOM?"
Enter
Type "echo '{}' > dummy.json"
Enter

Type "jq . dummy.json"
Enter

Type "ec validate input --file dummy.json --policy policy.yaml"
Enter
Wait
Type "# No violations, heh?"
Enter
Sleep 3s

########################
###### Filter SBOM #####
########################

Hide
Type "clear"
Enter
Show

Hide
# Go to the next commit - adds SBOM detection
Type@5ms "git checkout $(git rev-list --ancestry-path HEAD..main --reverse | head -n 1)"
Enter
Show

# Show what changed
Type "git --no-pager show HEAD"
Enter
Sleep 3s

Type "# Now dummy.json triggers SBOM not found violation"
Enter
Type "ec validate input --file dummy.json --policy policy.yaml"
Enter
Wait
Sleep 3s

Hide
Type "clear"
Enter
Show

Type "# Try validating an image - the policy does not know how to find the SBOM"
Enter
Type "ec validate image --policy policy.yaml"
Type "  --public-key 'https://security.access.redhat.com/data/63405576.txt'"
Type "  --ignore-rekor"
Type "  --image $IMAGE"
Enter
Wait
Sleep 3s

########################
###### Image SBOM ######
########################

Hide
Type "clear"
Enter
Show

Hide
# Go to the next commit - adds support for SBOM attestations on images
Type@5ms "git checkout $(git rev-list --ancestry-path HEAD..main --reverse | head -n 1)"
Enter
Show

# Show what changed
Type "git --no-pager show HEAD"
Enter
Sleep 3s

Hide
Type "clear"
Enter
Show

Type "# Image validation now works - finds the SBOM attestation"
Enter
Type "ec validate image --policy policy.yaml"
Type "  --public-key 'https://security.access.redhat.com/data/63405576.txt'"
Type "  --ignore-rekor"
Type "  --image $IMAGE"
Enter
Wait
Sleep 3s

Hide
Type "clear"
Enter
Show

Type "# Direct SBOM validation still works the same way"
Enter
Type "ec validate input --file sbom.json --policy policy.yaml"
Enter
Wait
Sleep 3s

########################
##### SBOM Attach ######
########################

Hide
Type "clear"
Enter
Show

# Go to the next commit - adds support for SBOM attachments
Type@5ms "git checkout $(git rev-list --ancestry-path HEAD..main --reverse | head -n 1)"
Enter

# Show what changed
Type "git --no-pager show HEAD"
Enter
Sleep 3s

Type "# Image validation now also evaluates the SBOM attachment"
Enter
Type "ec validate image --policy policy.yaml"
Type "  --public-key 'https://security.access.redhat.com/data/63405576.txt'"
Type "  --ignore-rekor"
Type "  --image $IMAGE"
Enter
Wait
Sleep 3s

Hide
Type "clear"
Enter
Show

Type "# Done!"
Enter
Sleep 3s
