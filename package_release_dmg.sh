#!/bin/bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="IPA Analyzer"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/dist/release}"
NOTARIZE="${NOTARIZE:-1}"
ENTITLEMENTS_PATH="${ENTITLEMENTS_PATH:-}"
VOLUME_NAME="${VOLUME_NAME:-$APP_NAME}"
ARCHITECTURES="${ARCHITECTURES:-arm64 x86_64}"
STAGING_PARENT="${TMPDIR:-/tmp}"
STAGING_PARENT="${STAGING_PARENT%/}"
CURRENT_STAGING_DIR=""

cleanup() {
    if [[ -n "$CURRENT_STAGING_DIR" && -d "$CURRENT_STAGING_DIR" ]]; then
        case "$CURRENT_STAGING_DIR" in
            "$STAGING_PARENT/ipa-analyzer-"*-dmg.*) rm -rf "$CURRENT_STAGING_DIR" ;;
            *) echo "Refusing to remove unexpected staging path: $CURRENT_STAGING_DIR" >&2 ;;
        esac
    fi
}
trap cleanup EXIT

usage() {
    printf '%s\n' \
        'Usage:' \
        '  SIGN_IDENTITY="Developer ID Application: Name (TEAMID)" \' \
        '  NOTARY_PROFILE="ipa-analyzer-notary" \' \
        '  ./package_release_dmg.sh' \
        '' \
        'Creates separate arm64 and x86_64 DMGs; it never merges architectures.' \
        '' \
        'Environment variables:' \
        '  SIGN_IDENTITY     Required Developer ID signing identity.' \
        '  NOTARY_PROFILE    Required notarytool keychain profile when NOTARIZE=1.' \
        '  NOTARIZE          Set to 0 for signed DMGs without Apple notarization.' \
        '  ARCHITECTURES      Space-separated list; default: arm64 x86_64.' \
        '  IPA_ANALYZER_VERSION App version; default: 0.1.0.' \
        '  ENTITLEMENTS_PATH Optional entitlements plist for the app.' \
        '  OUTPUT_DIR        DMG output directory; default: dist/release.' \
        '  VOLUME_NAME       Mounted DMG name; default: IPA Analyzer.'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi
if [[ $# -ne 0 ]]; then
    usage >&2
    exit 2
fi
if [[ "$NOTARIZE" != "0" && "$NOTARIZE" != "1" ]]; then
    echo "NOTARIZE must be 0 or 1." >&2
    exit 2
fi
if [[ -z "${SIGN_IDENTITY:-}" ]]; then
    echo "SIGN_IDENTITY is required." >&2
    echo "Run: security find-identity -v -p codesigning" >&2
    exit 2
fi
if [[ "$SIGN_IDENTITY" != "Developer ID Application:"* ]]; then
    echo "A Developer ID Application identity is required." >&2
    exit 2
fi
if [[ "$NOTARIZE" == "1" && -z "${NOTARY_PROFILE:-}" ]]; then
    echo "NOTARY_PROFILE is required when NOTARIZE=1." >&2
    exit 2
fi
if [[ -n "$ENTITLEMENTS_PATH" && ! -f "$ENTITLEMENTS_PATH" ]]; then
    echo "Entitlements file not found: $ENTITLEMENTS_PATH" >&2
    exit 2
fi
if ! security find-identity -v -p codesigning | grep -F -- "$SIGN_IDENTITY" >/dev/null; then
    echo "Signing identity is not installed or has no private key:" >&2
    echo "  $SIGN_IDENTITY" >&2
    exit 1
fi

for architecture in $ARCHITECTURES; do
    case "$architecture" in
        arm64|x86_64) ;;
        *)
            echo "Unsupported release architecture: $architecture" >&2
            exit 2
            ;;
    esac
done

download_notary_log() {
    local submission_id="$1"
    local architecture="$2"
    local log_path="$OUTPUT_DIR/notary-log-$architecture-$submission_id.json"
    if [[ -n "$submission_id" ]]; then
        xcrun notarytool log \
            "$submission_id" \
            --keychain-profile "$NOTARY_PROFILE" \
            "$log_path" || true
        [[ ! -f "$log_path" ]] || echo "Notary log: $log_path" >&2
    fi
}

verify_thin_bundle() {
    local app_path="$1"
    local expected_arch="$2"
    local executable="$app_path/Contents/MacOS/$APP_NAME"
    local actual_archs
    actual_archs="$(lipo -archs "$executable")"
    if [[ "$actual_archs" != "$expected_arch" ]]; then
        echo "Expected $expected_arch app executable, found '$actual_archs'." >&2
        exit 1
    fi

    while IFS= read -r -d '' binary_path; do
        if file "$binary_path" | grep -q 'Mach-O'; then
            actual_archs="$(lipo -archs "$binary_path")"
            if [[ "$actual_archs" != "$expected_arch" ]]; then
                echo "Expected $expected_arch, found '$actual_archs': $binary_path" >&2
                exit 1
            fi
        fi
    done < <(find "$app_path/Contents" -type f \( -perm -111 -o -name '*.dylib' -o -name '*.so' \) -print0)
}

notarize_dmg() {
    local dmg_path="$1"
    local architecture="$2"
    local result_path="$3"
    echo "Submitting $architecture DMG for notarization..."
    if ! xcrun notarytool submit \
        "$dmg_path" \
        --keychain-profile "$NOTARY_PROFILE" \
        --wait \
        --output-format json >"$result_path"; then
        cat "$result_path" >&2 || true
        local submission_id
        submission_id="$(plutil -extract id raw -o - "$result_path" 2>/dev/null || true)"
        download_notary_log "$submission_id" "$architecture"
        exit 1
    fi

    cat "$result_path"
    local submission_id status
    submission_id="$(plutil -extract id raw -o - "$result_path")"
    status="$(plutil -extract status raw -o - "$result_path")"
    if [[ "$status" != "Accepted" ]]; then
        echo "Notarization failed for $architecture with status: $status" >&2
        download_notary_log "$submission_id" "$architecture"
        exit 1
    fi

    xcrun stapler staple "$dmg_path"
    xcrun stapler validate "$dmg_path"
    codesign --verify --verbose=2 "$dmg_path"
    spctl \
        --assess \
        --type open \
        --context context:primary-signature \
        --verbose=4 \
        "$dmg_path"
}

mkdir -p "$OUTPUT_DIR"
IPA_ANALYZER_VERSION="${IPA_ANALYZER_VERSION:-0.1.0}"

for architecture in $ARCHITECTURES; do
    echo "Building $APP_NAME for $architecture..."
    PYINSTALLER_TARGET_ARCH="$architecture" \
        IPA_ANALYZER_VERSION="$IPA_ANALYZER_VERSION" \
        CODESIGN_IDENTITY="$SIGN_IDENTITY" \
        ENTITLEMENTS_PATH="$ENTITLEMENTS_PATH" \
        "$ROOT_DIR/scripts/build_macos_app.sh"

    app_path="$ROOT_DIR/dist/$architecture/$APP_NAME.app"
    executable="$app_path/Contents/MacOS/$APP_NAME"
    if [[ ! -x "$executable" ]]; then
        echo "App executable not found: $executable" >&2
        exit 1
    fi
    verify_thin_bundle "$app_path" "$architecture"

    echo "Verifying $architecture app signature..."
    codesign --verify --deep --strict --verbose=2 "$app_path"
    signature_details="$(codesign -d --verbose=4 "$app_path" 2>&1)"
    if ! grep -E 'flags=.*\(runtime\)' <<<"$signature_details" >/dev/null; then
        echo "Hardened Runtime is not enabled: $app_path" >&2
        exit 1
    fi

    staging_dir="$(mktemp -d "$STAGING_PARENT/ipa-analyzer-$architecture-dmg.XXXXXX")"
    CURRENT_STAGING_DIR="$staging_dir"
    result_path="$staging_dir/notary-result.json"
    dmg_path="$OUTPUT_DIR/IPA-Analyzer-$IPA_ANALYZER_VERSION-macOS-$architecture.dmg"

    ditto "$app_path" "$staging_dir/$APP_NAME.app"
    ln -s /Applications "$staging_dir/Applications"

    echo "Creating DMG: $dmg_path"
    hdiutil create \
        -volname "$VOLUME_NAME" \
        -srcfolder "$staging_dir" \
        -format UDZO \
        -ov \
        "$dmg_path"

    echo "Signing DMG: $dmg_path"
    codesign \
        --force \
        --sign "$SIGN_IDENTITY" \
        --timestamp \
        "$dmg_path"
    codesign --verify --verbose=2 "$dmg_path"

    if [[ "$NOTARIZE" == "1" ]]; then
        notarize_dmg "$dmg_path" "$architecture" "$result_path"
    else
        echo "NOTARIZE=0: $architecture DMG is signed but not notarized."
    fi
    rm -rf "$staging_dir"
    CURRENT_STAGING_DIR=""
    echo "Release package ready: $dmg_path"
done
