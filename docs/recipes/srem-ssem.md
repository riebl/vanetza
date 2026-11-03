Title: Build SREM and SSEM messages

# How to build SREM and SSEM messages

`vanetza/facilities/priority_functions.hpp` provides builders for the Traffic Light Control messages:
`SignalRequestMessage` (SREM) and `SignalStatusMessage` (SSEM).
The builders fill the body of a message object allocated by the caller; they do not touch the ITS header,
do not send anything, and do not track any request state. They are message construction helpers only,
not a priority state machine, transport, or proof that a controller granted priority.
The example below builds a synthetic request and answers it with a `processing` status,
which means that the request is being handled, not that priority was granted.

```cpp
#include <vanetza/asn1/its/IntersectionAccessPoint.h>
#include <vanetza/asn1/its/RequestorType.h>
#include <vanetza/asn1/its/SignalRequestList.h>
#include <vanetza/asn1/its/SignalRequestPackage.h>
#include <vanetza/asn1/its/SignalRequesterInfo.h>
#include <vanetza/asn1/its/SignalStatus.h>
#include <vanetza/asn1/its/SignalStatusPackage.h>
#include <vanetza/asn1/its/VehicleID.h>
#include <vanetza/asn1/srem.hpp>
#include <vanetza/asn1/ssem.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/facilities/priority_functions.hpp>
#include <chrono>
#include <iostream>
#include <string>

int main()
{
    using namespace vanetza;
    using namespace vanetza::facilities;

    const Clock::time_point now = Clock::at("2026-10-03 10:15:30.250"); // UTC

    // Synthetic SREM: one priority request at one intersection.
    asn1::Srem srem;
    srem->header.protocolVersion = 2;
    srem->header.messageID = ItsPduHeader__messageID_srem;
    srem->header.stationID = 4711;
    srem->srm.sequenceNumber = asn1::allocate<MsgCount_t>();
    *srem->srm.sequenceNumber = 5;

    set_timestamp(srem->srm, now);
    set_requestor(srem->srm, 4711, BasicVehicleRole_publicTransport);

    PriorityRequest request;
    request.intersection_id = 42;
    request.request_id = 1;
    request.request_type = PriorityRequestType_priorityRequest;
    request.inbound_lane = 2;
    request.outbound_lane = 10;
    request.arrival = now + std::chrono::seconds(20);
    request.duration = std::chrono::seconds(8);
    add_request(srem->srm, request);

    std::string error;
    if (!srem.validate(error)) {
        std::cerr << "SREM validation failed: " << error << '\n';
        return 1;
    }

    asn1::Srem decoded_srem;
    if (!decoded_srem.decode(srem.encode())) {
        std::cerr << "SREM decoding failed\n";
        return 2;
    }

    const SignalRequestMessage_t& srm = decoded_srem->srm;
    if (!srm.requests || srm.requests->list.count != 1) {
        std::cerr << "SREM request list mismatch\n";
        return 3;
    }
    const SignalRequestPackage_t& request_package = *srm.requests->list.array[0];
    if (request_package.request.id.id != 42 ||
            !request_package.request.outBoundLane ||
            request_package.request.outBoundLane->choice.lane != 10 ||
            !request_package.duration || *request_package.duration != 8000) {
        std::cerr << "SREM request content mismatch\n";
        return 4;
    }

    // Synthetic SSEM: the intersection reports the request as processing.
    asn1::Ssem ssem;
    ssem->header.protocolVersion = 2;
    ssem->header.messageID = ItsPduHeader__messageID_ssem;
    ssem->header.stationID = 1;
    set_timestamp(ssem->ssm, now);

    SignalStatus& signal_status = add_status(ssem->ssm, 42, 3);
    PriorityResponse response;
    response.requester = 4711;
    response.request_id = 1;
    response.request_sequence = 5;
    response.role = BasicVehicleRole_publicTransport;
    response.inbound_lane = 2;
    response.outbound_lane = 10;
    response.status = PrioritizationResponseStatus_processing;
    add_response(signal_status, response);

    if (!ssem.validate(error)) {
        std::cerr << "SSEM validation failed: " << error << '\n';
        return 5;
    }

    asn1::Ssem decoded_ssem;
    if (!decoded_ssem.decode(ssem.encode())) {
        std::cerr << "SSEM decoding failed\n";
        return 6;
    }

    const SignalStatusMessage_t& ssm = decoded_ssem->ssm;
    if (ssm.status.list.count != 1) {
        std::cerr << "SSEM status list mismatch\n";
        return 7;
    }
    const SignalStatus_t& decoded_status = *ssm.status.list.array[0];
    if (decoded_status.id.id != 42 || decoded_status.sequenceNumber != 3 ||
            decoded_status.sigStatus.list.count != 1) {
        std::cerr << "SSEM status content mismatch\n";
        return 8;
    }
    const SignalStatusPackage_t& response_package = *decoded_status.sigStatus.list.array[0];
    if (!response_package.requester ||
            response_package.requester->id.choice.stationID != 4711 ||
            response_package.status != PrioritizationResponseStatus_processing) {
        std::cerr << "SSEM response content mismatch\n";
        return 9;
    }

    std::cout << "SREM and SSEM round-trip OK\n";
    return 0;
}
```

The helpers do not set the ITS header: fill `protocolVersion`, `messageID` and `stationID` yourself.
The caller also sets the SREM sequence number (`srm.sequenceNumber`);
for an SSEM, each `SignalStatus` gets its sequence number as the third argument of `add_status`.
`set_requestor` replaces a previous requestor, including one from a decoded message,
and adds `hpmsType` only when the optional `vehicle_type` argument is given.

## Build the example

Save the program as `main.cpp`, next to this `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.16)
project(priority_example LANGUAGES C CXX)
find_package(Vanetza REQUIRED)
add_executable(priority_example main.cpp)
target_compile_features(priority_example PRIVATE cxx_std_14)
target_link_libraries(priority_example PRIVATE Vanetza::facilities)
```

Use a Vanetza installation containing these builders, or a Vanetza build tree
configured with `-DVANETZA_EXPORT_PACKAGE=ON`. For the latter:

```sh
cmake -S . -B build -DVanetza_DIR=/path/to/vanetza/build
cmake --build build --target priority_example
./build/priority_example
```

The expected output is `SREM and SSEM round-trip OK`. See
[the build instructions](../how-to-build.md#integrating-vanetza) for integrating
an installed package. Validation and encoding can throw; applications should
handle these errors according to their own input and recovery policy.

## Identifiers

The builders take `unsigned` identifiers and copy them into the generated ASN.1 fields.
The documented ranges follow the ASN.1 constraints: `intersection_id` 0..65535, `request_id` 0..255,
inbound and outbound lane identifiers 0..255, and `request_sequence` 0..127 in a response.
The helpers do not clamp or check these values; `validate()` and `encode()` enforce the ASN.1
constraints. Check the values in your own code to fail early.

## Time and duration

`Clock::at` creates the UTC-based time point. `set_timestamp` stores the minute of the year and
the millisecond within that minute. `PriorityRequest::duration` is a `Clock::duration` and is encoded as
`DSecond`, an integer number of milliseconds in 0..65535.
`add_request` checks the range on the original duration, before converting to milliseconds:
it throws `std::out_of_range` unless 0 <= duration <= 65.535 s. In particular, 65.535 s plus one
microsecond is rejected even though truncation would produce 65535, and negative durations are rejected.
Sub-millisecond fractions within the range are truncated (1500 microseconds becomes 1 ms).
A rejected request is not appended.

## Optional fields and empty lists

`outbound_lane`, `arrival` and `duration` in `PriorityRequest`, and `outbound_lane` in
`PriorityResponse`, are `boost::optional`. An unset value leaves the ASN.1 field absent;
an outbound lane or duration set to zero remains present. Absence and a present zero differ on the wire.
The same applies to the request list: `message.requests` stays null until the first `add_request`,
and the SSEM status list stays empty until the first `add_status`.
An SSEM needs at least one status (`SignalStatusList` has size 1..32), so encoding an SSEM
without `add_status` throws `std::runtime_error`.

## Ownership and errors

`add_status` returns a reference to the status appended to the `SignalStatusMessage`.
The message owns that object: use the reference only while the message is alive and do not free it. The message wrapper also owns its allocated sequence-number field.
`add_response` appends a response package to this status. `validate(error)` returns false and fills
`error`; `encode()` throws `std::runtime_error` if ASN.1 constraints are violated; `add_request`
throws `std::out_of_range` for an out-of-range duration; allocation failures surface as
`asn1::asn1c_exception`.
