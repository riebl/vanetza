#ifndef PERMISSIONS_HPP_
#define PERMISSIONS_HPP_

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/its_aid.hpp>
#include <cstdlib>
#include <map>
#include <memory>
#include <utility>

namespace vanetza {
namespace security {

class PermissionChecker {
public:
    virtual bool check(const ItsAid aid, const ByteBuffer& permissions, const ByteBuffer& requested) = 0;
};

class VersionedSSPChecker : public PermissionChecker {
public:
    bool check(const ItsAid aid, const ByteBuffer& permissions, const ByteBuffer& requested) override;
};

class TlcPermissionChecker : public PermissionChecker {
public:
    bool check(const ItsAid aid, const ByteBuffer& permissions, const ByteBuffer& requested) override;
};

namespace {
/**
 * Most SSP definitions consist of two types of bits:
 * - Bits that must match exactly in request and AT, e.g. the version number part, identifiers (like with IVIM) or reserved bits
 * - Bits that grant individual permissions and can only be successfully requested if they are set in the AT
 *
 * For easy bytewise SSP checking, one can use bitmasks to mark where which type of check is required.
 *
 * This map contains such a bitmask for all supported applications per supported SSP version of the respective application.
 */
static std::map<ItsAid, std::map<uint8_t, ByteBuffer>> check_masks {
    { aid::CA, {{ 0x01, ByteBuffer { 0xFF, 0x00, 0x03 } }} },
    { aid::DEN, {{ 0x01, ByteBuffer { 0xFF, 0x00, 0x00, 0x00 } }} },
    { aid::TLM, {{ 0x01, ByteBuffer { 0xFF, 0x1F } }} },
    { aid::RLT, {{ 0x01, ByteBuffer { 0xFF, 0x3F } }} },
    { aid::IVI, {{ 0x01, ByteBuffer { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x07 } }} },
    { aid::TLC, {{ 0x01, ByteBuffer { 0xFF, 0x00, 0x02 } }} }
};

/**
 * For the applications / SSP versions above, a generic checker can be used that only needs the bitmask.
 */
static const std::shared_ptr<VersionedSSPChecker> default_versioned_ssp_checker = std::make_shared<VersionedSSPChecker>(VersionedSSPChecker {});

/**
 * This map contains specific SSP checkers for some applications with special requirements.
 */
static const std::map<ItsAid, std::shared_ptr<PermissionChecker>> specific_checkers {
    { aid::TLC, std::make_shared<TlcPermissionChecker>(TlcPermissionChecker{}) }};
}

/**
 * For a specific application, check whether the available permissions satisfy a request.
 *
 * \param aid AID of the application for which the check is to be performed
 * \param permissions check against these available permissions
 * \param requested which permissions are requested/needed (e.g. for signing/verifying)
 */
bool check_permissions(const ItsAid aid, const ByteBuffer& permissions, const ByteBuffer& requested);

} // namespace security
} // namespace vanetza

#endif /* PERMISSIONS_HPP_ */
