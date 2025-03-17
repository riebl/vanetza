@0xcb50be3531badf53;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("vanetza::linklayer");

enum ErrorCode
{
    ok @0;
    invalidArgument @1;
    unsupported @2;
    internalError @3;
}

interface LinkLayer
{
    enum Capabilities
    {
        ocb11p @0;
        ocb11bd @1;
        cv2xLte @2;
        cv2x5G @3;
    }

    struct Frame
    {
        sourceAddress @0 :Data;
        destinationAddress @1 :Data;
        payload @2 :Data;

        parameters :union
        {
            unspecified @3 :Void;
            wlan @4 :WlanParameters;
            cv2x @5 :Cv2xParameters;
        }
    }

    struct WlanParameters {
        # Parameters for WLAN devices in OCB mode (IEEE 802.11 p and bd)
        priority @0 :UInt8;     # 802.1 user priority (0-7)
        power @1 :Int16;        # dBm scaled by 8
        datarate @2 :UInt16;    # Mbps scaled by 2 (500kbps steps)
    }

    struct Cv2xParameters
    {
        # Parameters for C-V2X devices (LTE-V2X and 5G-V2X)
        priority @0 :UInt8;     # PPPP (0-7)
        power @1 :Int16;        # dBm scaled by 8
    }

    interface DataListener
    {
        onDataIndication @0 (data :Frame);
    }

    struct ChannelBusyRatio
    {
        busy @0 :UInt16;        # number of samples sensed as busy
        samples @1 :UInt16;     # total number of samples in measurement interval
    }

    interface CbrListener
    {
        onCbrReport @0 (cbr :ChannelBusyRatio);
    }

    struct TxResult
    {
        error @0 :ErrorCode;
        message @1 :Text;
    }

    getCapabilities @0 () -> (capabilities :List(Capabilities));
    transmitData @1 (request :Frame) -> (result :TxResult);
    subscribeData @2 (sink :DataListener);
    subscribeCbr @3 (sink :CbrListener);
    setSourceAddress @4 (address :Data) -> (result :ErrorCode);
}
