from enum import IntEnum

class DeviceType(IntEnum):
    InsulinPump = 0x1
    GlucoseSensor = 0x2
    BloodGlucoseMeter = 0x3

    # alias for the same
    MobileApplication = 0x4 
    SecondaryDisplay = 0x4

    CareLinkUploadApplication = 0x5
    FirmwareUpdateApplication = 0x6
    DiagnosticApplication = 0x7
    PrimaryDisplay = 0x8