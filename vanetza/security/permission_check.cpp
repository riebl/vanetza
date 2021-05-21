#include <vanetza/security/permission_check.hpp>
#include <algorithm>
#include <cstring>

namespace vanetza {
namespace security {

bool check_bits(const ByteBuffer& mask, const ByteBuffer& permissions, const ByteBuffer& requested) {
    for (auto i = 0; i < mask.size(); i++) {
        // Check whether a requested bit is not set (first part)
        // or if the bits differ in parts requiring exact matching (first and second part).
        if (requested[i] & ~permissions[i] | mask[i] & ~requested[i] & permissions[i]) {
            return false;
        }
    }
    return true;
}

bool VersionedSSPChecker::check(ItsAid aid, const ByteBuffer& permissions, const ByteBuffer& requested) {
    auto size = permissions.size();
    if (requested.size() != size) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    // Check version byte
    if (auto version = requested[0] == permissions[0]) {
        auto aid_masks = check_masks.find(aid);
        if (aid_masks != check_masks.end()) {
            auto version_mask = aid_masks->second.find(version);
            if (version_mask != aid_masks->second.end()) {
                auto mask = version_mask->second;
                if (mask.size() == size) {
                    return check_bits(mask, permissions, requested);
                }
            }
        }
    }
    // Different versions, AID not supported or version not supported
    return false;
}

bool TlcPermissionChecker::check(ItsAid aid, const ByteBuffer& permissions, const ByteBuffer& requested) {
    if (aid != aid::TLC) {
        return false;
    }
    auto size = permissions.size();
    // SSEM / SREM SSPs are not zero bytes long
    if (requested.size() != size || size == 0) {
       return false;
    }
    // Check version byte
    if (auto version = requested[0] == permissions[0]) {
        if (version == 1) {
            if (size == 1) {
                // SSEM (does not have specific permissions)
                return true;
            } else {
                // SREM
                return default_versioned_ssp_checker->check(aid, permissions, requested);
            }
        }
    }
    // Different versions or version not supported
    return false;
}

bool check_permissions(const ItsAid aid, const ByteBuffer& permissions, const ByteBuffer& requested) {
    auto it = specific_checkers.find(aid);
    if (it != specific_checkers.end()) {
        it->second->check(aid, permissions, requested);
    }
    return default_versioned_ssp_checker->check(aid, permissions, requested);
}

} // namespace security
} // namespace vanetza
