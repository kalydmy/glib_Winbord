# CHANGELOG

<!--- next entry here -->

## 0.17.1
2024-01-10

### API
  A few API functions were changed to support Q3 flash. a new definition is introduced, `Q2_API`. User can use this definition to keep the old API for Q2 flash.
  The new API changes are listed below:
- API function `QLIB_AuthPlainAccess_Grant` name changed to `QLIB_PlainAccessGrant`
- new API function `QLIB_PlainAccessRevoke` was introduced to replace `QLIB_AuthPlainAccess_Revoke` and `QLIB_PlainAccessEnable`.
  It performs either Authenticated plain access grant or non-authenticated grant according to section policy. 
  The new function also perform non-authenticated plain access revoke for Q3 
- `QLIB_Format` function - added a new parameter for Q3, to support default configuration of the flash as legacy flash after format.
   The new prototype is:
```C
  QLIB_STATUS_T QLIB_Format(QLIB_CONTEXT_T* qlibContext, const KEY_T deviceMasterKey, BOOL eraseDataOnly, BOOL factoryDefault);
``` 
- `QLIB_ConfigDevice` function - two new parameters were added for Q3 LMS keys and pre-provisioning master key.
  The new prototype is:
```C
  QLIB_STATUS_T QLIB_ConfigDevice(QLIB_CONTEXT_T*                   qlibContext,
                                const KEY_T                       deviceMasterKey,
                                const KEY_T                       deviceSecretKey,
                                const QLIB_SECTION_CONFIG_TABLE_T sectionTable[QLIB_NUM_OF_DIES],
                                const KEY_ARRAY_T                 restrictedKeys[QLIB_NUM_OF_DIES],
                                const KEY_ARRAY_T                 fullAccessKeys[QLIB_NUM_OF_DIES],
                                const QLIB_LMS_KEY_ARRAY_T        lmsKeys[QLIB_NUM_OF_DIES],
                                const KEY_T                       preProvisionedMasterKey,
                                const QLIB_WATCHDOG_CONF_T*       watchdogDefault,
                                const QLIB_DEVICE_CONF_T*         deviceConf,
                                const _128BIT                     suid);
```
  - In addition we added to the device configuration structure the following fields:
    -  `ctagModeMulti`(BOOL) - this field is relevant only for Q2 128 flash
    -  `lock`(BOOL) - this field is relevant only for Q3 flash. must be set to FALSE for Q2 chip
    -  `bootFailReset`(BOOL)- this field will be supported only from Q3 rev B. currently must be set to FALSE
    -  `resetPA` - this field is relevant only for Q3 flash. must be set to FALSE for all sections other then section 0 in Q2
    -  `vaultSize` - this field is relevant only for Q3 flash. must be set to 0 for Q2 chip
    -  `fastReadDummyCycles` - this field is relevant only for Q3 flash. ignored for Q2 chip
- `QLIB_ConfigSection` function - swap parameter was split to two parameters: swap and action, to determine also whether to reload the section configuration.
  The new prototype is:
```C
  QLIB_STATUS_T QLIB_ConfigSection(QLIB_CONTEXT_T*            qlibContext,
                                 U32                        sectionID,
                                 const QLIB_POLICY_T*       policy,
                                 const U64*                 digest,
                                 const U32*                 crc,
                                 const U32*                 newVersion,
                                 BOOL                       swap,
                                 QLIB_SECTION_CONF_ACTION_T action);
```
- `QLIB_Watchdog_Get` function - secondsPassed & ticksResidue parameters were replaced by milliSecondsPassed, such that the timer value is returned in milliseconds instead of seconds.
  The new prototype is:
```C
  QLIB_STATUS_T QLIB_Watchdog_Get(QLIB_CONTEXT_T* qlibContext, U32* milliSecondsPassed, BOOL* expired);
``` 
- Platform Hash functions API changed. User should implement the new prototype as follows:
```C
  int PLAT_HASH_Init(void** ctx, QLIB_HASH_OPT_T opt);
  int PLAT_HASH_Update(void* ctx, const void* data, uint32_t dataSize);
  int PLAT_HASH_Finish(void* ctx, uint32_t* output);
```
- `InitDevice` function `busFormat` parameter should receive specific SPI bus mode. autosense option to keep current mode was removed.
- `QLIB_INIT_AFTER_Q2_POWER_UP` definition changed to `QLIB_INIT_AFTER_FLASH_POWER_UP`
- `QLIB_INIT_BUS_MODE` was replaced by `QLIB_INIT_BUS_FORMAT`. e.g QLIB_INIT_BUS_FORMAT=QLIB_BUS_FORMAT(QLIB_BUS_MODE_1_1_1, FALSE)
- `Q2_AWDT_IS_CALIBRATED` changed to `W77Q_AWDT_IS_CALIBRATED`.
-  RPMC API functions were removed.

### Features

- add Q3 chip support
- remove QLIB_TARGET of specific target. support only all_targets flavor to detect flash type
  Note that for qconf sample, user should define QCONF_TARGET to specific flash target.
- remove pyqlib
- QLIB_Format that deletes the flash registers, will now perform reset to flash to load the new registers configuration 
- Added several samples to demonstrate Q3 new features: LMS Attestation, LMS FW Update, Vault and Secure Log samples
- Added scripts/lms/lms_tool.py script to create LMS commands (used in LMS FW Update sample) 

### Performance results

| secure   read   |         |        |              |       |         |       |               |       |         |       |               |       |         |       |
|-----------------|---------|--------|--------------|-------|---------|-------|---------------|-------|---------|-------|---------------|-------|---------|-------|
|                 |  Tavor  |        |              |       |         |       |               |       |         |       |               |       |         |       |
|                 |  Q32JW  |        | q32JW Q2_API |       |  Q128JW |       | Q128JW Q2_API |       |  Q128JV |       | Q128JV Q2_API |       | Q256    |       |
|                 | 100 Mhz |        |    100 Mhz   |       | 135 Mhz |       |    135 Mhz    |       | 135 Mhz |       |    135 Mhz    |       | 135 Mhz |       |
|                 |   usec  |  MB/s  |     usec     |  MB/s |   usec  |  MB/s |      usec     |  MB/s |   usec  |  MB/s |      usec     |  MB/s | usec    | MB/s  |
| Single SPI      |    78   |  3.282 |      78      | 3.282 |    68   | 3.765 |       69      | 3.710 |    67   | 3.821 |       68      | 3.765 |    80   | 3.200 |
| Quad  SPI 1_4_4 |    68   | 3.3879 |      66      | 3.879 |    61   | 4.197 |       62      | 4.129 |    61   | 4.197 |       62      | 4.129 |    74   | 3.459 |
| QPI             |    NS   |   NS   |      NS      |   NS  |    62   | 4.129 |       62      | 4.129 |    61   | 4.197 |       62      | 4.129 |    74   | 3.459 |
|                 |         |        |              |       |         |       |               |       |         |       |               |       |         |       |
| secure write    |         |        |              |       |         |       |               |       |         |       |               |       |         |       |
|                 |  Tavor  |        |              |       |         |       |               |       |         |       |               |       |         |       |
|                 |  Q32JW  |        | Q32JW Q2_API |       |  Q128JW |       | Q128JW Q2_API |       |  Q128JV |       | Q128JV Q2_API |       | Q256    |       |
|                 | 100 MHz |        |    100 MHz   |       | 135 MHz |       |    135 Mhz    |       | 135 Mhz |       |    135 Mhz    |       | 135 Mhz |       |
|                 |   usec  |  MB/s  |     usec     |  MB/s |   usec  |  MB/s |      usec     |  MB/s |   usec  |  MB/s |      usec     |  MB/s | usec    | MB/s  |
| Single SPI      |   887   |  0.289 |      888     | 0.288 |   776   | 0.330 |      773      | 0.331 |   770   | 0.332 |      770      | 0.332 | 865     | 0.296 |
| Quad SPI 1_4_4  |   890   |  0.288 |      888     | 0.288 |   773   | 0.331 |      771      | 0.332 |   761   | 0.336 |      758      | 0.338 | 859     | 0.298 |
| QPI             |    NS   |   NS   |      NS      |   NS  |   764   | 0.335 |      765      | 0.335 |   761   | 0.336 |      759      | 0.337 | 857     | 0.299 |

- NS - not supported

## 0.17.0
2024-01-03

### Internal version
- This version is for internal testing use.

## 0.16.2
2023-07-09

### API
- change platform hash function to receive void* input buffer instead of U32*.
  The new prototype is:
```C
  void PLAT_HASH(uint32_t* output, const void* data, uint32_t dataSize);
```

### Features:
- Add 64Mbit flash (1.8 & 3.3) to release

### Fixes
- Add pyQlib's readme file
- Fix QLIB_GetSectionConfiguration for formatted chip


### Performance results

|secure read| | | | | | | | | | | | |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| |**NXP-1050**| | | | | |**NXP-LPC54005**| | | | | |
| |**Q32**| |**Q128**| |**Q128jv**| |**Q32**| |**Q128**| |**Q128jv**| |
| |**105 Mhz**| |**133 Mhz**| |**133 Mhz**| |**60 Mhz**| |**60 Mhz**| |**60 Mhz**| |
| |**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|
|**Single SPI**|70|3.657|63|4.063|62|4.129|94|2.723|92|2.783|90|2.844|
|**Quad  SPI 1_4_4**|58|4.414|55|4.655|54|4.741|62|4.129|62|4.129|60|4.267|
|**QPI**|NS|NS|55|4.655|54|4.741|NS|NS|58|4.414|58|4.414|

|secure write| | | | | | | | | | | | |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| |**NXP-1050**| | | | | |**NXP-LPC54005**| | | | | |
| |**Q32**| |**Q128**| |**Q128jv**| |**Q32**| |**Q128**| |**Q128jv**| |
| |**105 MHz**| |**105 MHz**| |**105 MHz**| |**60 Mhz**| |**60 Mhz**| |**60 Mhz**| |
| |**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|
|**Single SPI**|889|0.288|765|0.335|774|0.331|907|0.282|830|0.308|800|0.320|
|**Quad SPI 1_4_4**|880|0.291|758|0.338|756|0.339|877|0.292|803|0.319|761|0.336|
|**QPI**|NS|NS|748|0.342|755|0.339|NS|NS|790|0.324|763|0.336|

- NS - not supported

## 0.16.1
2023-01-22

### API
- **qlib_platform.h:** rename `PLAT_SPI_WriteReadTransaction_V2` to `PLAT_SPI_WriteReadTransaction`

### Features:
- **Samples:** Add sample for QLIB initialization and GetId

### Fixes
- **QLIB support for 16bits mcu:** - Make QLIB agnostic to 'int' bit size by changing QLIB types in qlib_defs.h to C99 standard
- **pyqlib:** remove old implementation of pyqlib
- **pyqlib:** make sure pyqlib is working correctly for both x86 and x64 architectures.
- **pyqlib:** update bus format in PyQlib and its sample
- **deliverables:** rename deliverables folders names. from w77q128 to w77q128jw and from w77q32 to w77q32jw


### Performance results

|secure read| | | | | | | | | | | | |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| |**NXP-1050**| | | | | |**NXP-LPC54005**| | | | | |
| |**Q32**| |**Q128**| |**Q128jv**| |**Q32**| |**Q128**| |**Q128jv**| |
| |**105 Mhz**| |**133 Mhz**| |**133 Mhz**| |**60 Mhz**| |**60 Mhz**| |**60 Mhz**| |
| |**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|
|**Single SPI**|70|3.657|63|4.063|62|4.129|92|2.783|90|2.844|88|2.909|
|**Quad  SPI 1_4_4**|59|4.339|55|4.655|54|4.741|59|4.339|59|4.4339|58|4.414|
|**QPI**|NS|NS|55|4.655|54|4.741|NS|NS|55|4.665|55|4.655|

|secure write| | | | | | | | | | | | |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| |**NXP-1050**| | | | | |**NXP-LPC54005**| | | | | |
| |**Q32**| |**Q128**| |**Q128jv**| |**Q32**| |**Q128**| |**Q128jv**| |
| |**105 MHz**| |**105 MHz**| |**105 MHz**| |**60 Mhz**| |**60 Mhz**| |**60 Mhz**| |
| |**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|
|**Single SPI**|823|0.311|732|0.350|775|0.330|901|0.284|827|0.310|806|0.318|
|**Quad SPI 1_4_4**|824|0.311|721|0.355|753|0.340|870|0.294|797|0.321|762|0.336|
|**QPI**|NS|NS|713|0.359|757|0.338|NS|NS|786|0.326|762|0.336|

- NS - not supported

## 0.16.0
2022-11-11

### API

- SPI interface - Replace old platform function `PLAT_SPI_WriteReadTransaction` with `PLAT_SPI_WriteReadTransaction_V2`. 
  In new function, the `dtr` parameter is replaced by `flags`, and the `command`, `address` and `dataOut` are grouped in `dataOutStream` output buffer.   
  For backward compatibility, user can define `QLIB_PLATFORM_V1` to use old version.
- Remove `PLAT_SPI_SetDirectAccessMode`.

### Features
- Add `QLIB_SAMPLE_SignVerify` sample code for `data signing by flash` feature.
- Add a new Python wrapper using SWIG.

### Fixes

- Set default value for `AWDT` if user doesn't provide one in configDevice.
- Remove reset after `QLIB_Format` and from `QLIB_configDevice` in case `GMC` and `GMT` registers haven't changed.
- Add reset on `initDevice` to load volatile registers.
- Add timeout on chip initialization, in case the chip doesn't become ready.
- Flash reset sets address mode according to default `ADP` field instead of the the pre-reset value
- Remove internal debug features

### Performance results

|secure read| | | | | | | | | | | | |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| |**NXP-1050**| | | | | |**NXP-LPC54005**| | | | | |
| |**Q32**| |**Q128**| |**Q128jv**| |**Q32**| |**Q128**| |**Q128jv**| |
| |**105 Mhz**| |**133 Mhz**| |**133 Mhz**| |**60 Mhz**| |**60 Mhz**| |**60 Mhz**| |
| |**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|
|**Single SPI**|71|3.606|63|4.063|61|4.197|92|2.783|90|2.844|88|2.909|
|**Quad  SPI 1_4_4**|59|4.339|54|4.741|54|4.741|59|4.339|59|4.4339|58|4.414|
|**QPI**|NS|NS|54|4.741|54|4.741|NS|NS|56|4.571|55|4.655|

|secure write| | | | | | | | | | | | |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| |**NXP-1050**| | | | | |**NXP-LPC54005**| | | | | |
| |**Q32**| |**Q128**| |**Q128jv**| |**Q32**| |**Q128**| |**Q128jv**| |
| |**105 MHz**| |**105 MHz**| |**105 MHz**| |**60 Mhz**| |**60 Mhz**| |**60 Mhz**| |
| |**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|
|**Single SPI**|808|0.317|731|0.350|771|0.332|901|0.284|827|0.310|806|0.318|
|**Quad SPI 1_4_4**|805|0.318|723|0.354|753|0.340|870|0.294|797|0.321|764|0.335|
|**QPI**|NS|NS|711|0.360|758|0.338|NS|NS|786|0.326|765|0.335|

- NS - not supported

## 0.15.1.1
2022-10-13

### Internal version
- This version is for internal use. 
- This is NOT a version for clients

### API

- Replace old platform function PLAT_SPI_WriteReadTransaction with PLAT_SPI_WriteReadTransaction_V2. 
  In new function, the dtr parameter is replaced by flags.
  For backward compatibility, user can define QLIB_PLATFORM_V1 to use old version.
- Remove PLAT_SPI_SetDirectAccessMode.

### Features
- Add QLIB_SAMPLE_SignVerify sample code for `data signing by flash` feature. 

### Fixes

- Set default value for AWDT if user doesn't provide one in configDevice
- Remove reset after QLIB_Format and from QLIB_configDevice in case GMC and GMT registers haven't changed.
- Add reset on initDevice to load volatile registers
- Add timeout on initialization of the chip, in case chip doesn't become ready.
- Flash reset sets address mode according to default ADP field instead of the the pre-reset value
- Remove some debug internal features


## 0.15.0.1
2022-06-02

### Internal version
- This version is for SW team internal development purposes. 
- This is NOT a version for clients

### Features

- Docker - Add Docker container to CI jobs, each build stage JOB will execute in the same Docker container
- Remove process duplication in CI - "Release final" now takes artifacts from make_deliverables job, instead of re-running the make_deliverables script by itself

### Fixes

- Server/client - x64 option is now working for server/client tests
- Fixing code format Perl script
- Move generate_tests.bat to gitlab-trigger-tools generic folder
- Extinguish warnings in remote compilation & spellcheck
- Change all batch file to have better root path handling
- Fix server and client visual projects for compilation for x64 solution
- pyqlib use threads in Linux server as in windows
- Move Linux generation code from WSL to native Linux jobs
- Allow some RUN tests to run outside of docker using custom script
- Allowing custom before_script for all test jobs
- verify reset succeeded by checking that DMC was incremented after reset command

## 0.14.0
2022-04-29

### API
- Add `data signing by flash` feature using the following new API:
```C
  QLIB_STATUS_T QLIB_Sign(QLIB_CONTEXT_T* qlibContext, U32 sectionID, U8* dataIn, U32 dataSize, _256BIT signature);
  QLIB_STATUS_T QLIB_Verify(QLIB_CONTEXT_T* qlibContext, U32 sectionID, U8* dataIn, U32 dataSize, const _256BIT signature);
```
  To enable this feature define `QLIB_SIGN_DATA_BY_FLASH`
- Remove `PLAT_Init` function from the platform file

### Features
- Add new 3.3v target - `w77q128jv`
  - Added new section policy bit `AUTH_PROT_AC` for integrity on access - **backwards compatible**
- `QLIB_GetHWVersion` can be called even before the device is initialized using `QLIB_InitDevice` - **backwards compatible**
- Miscellaneous Bug fixes - **backwards compatible**
- Add new client/server code using new architecture - the new architecture simplifies the client/server usage. In order to use QLIB in client/server mode, the user needs to define only a few integration function. These functions are described in the client/server deliverables - **not backwards compatible**
- Modify Pyqlib to adjust to the new client/server architecture and add a new usage sample code - **not backwards compatible**
- Rename `QCONF_NO_DIRECT_FLASH_ACCESS` to `QLIB_NO_DIRECT_FLASH_ACCESS`, added `QCONF_STRUCT_ON_RAM` definition. More details can be found in the user manual - **not backwards compatible**

### Performance results

|secure read| | | | | | | | | | | | |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| |**NXP-1050**| | | | | |**NXP-LPC54005**| | | | | |
| |**Q32**| |**Q128**| |**Q128jv**| |**Q32**| |**Q128**| |**Q128jv**| |
| |**105 Mhz**| |**133 Mhz**| |**133 Mhz**| |**60 Mhz**| |**60 Mhz**| |**60 Mhz**| |
| |**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|
|**Single SPI**|70|3.657|63|4.063|61|4.197|91|2.813|89|2.876|87|2.943|
|**Quad  SPI 1_4_4**|58|4.414|53|4.830|53|4.830|59|4.339|57|4.491|56|4.571|
|**QPI**|NS|NS|55|4.655|54|4.741|NS|NS|55|4.655|53|4.830|

|secure write| | | | | | | | | | | | |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| |**NXP-1050**| | | | | |**NXP-LPC54005**| | | | | |
| |**Q32**| |**Q128**| |**Q128jv**| |**Q32**| |**Q128**| |**Q128jv**| |
| |**105 MHz**| |**105 MHz**| |**105 MHz**| |**60 Mhz**| |**60 Mhz**| |**60 Mhz**| |
| |**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|**usec**|**MB/s**|
|**Single SPI**|856|0.299|747|0.343|443|0.578|887|0.289|813|0.315|612|0.418|
|**Quad SPI 1_4_4**|801|0.320|739|0.346|424|0.604|855|0.299|783|0.327|543|0.471|
|**QPI**|NS|NS|729|0.351|425|0.602|NS|NS|772|0.332|553|0.463|

- NS - not supported

## 0.13.3
2022-02-17

### API

- New API to support RPMC feature:
```C
  QLIB_STATUS_T QLIB_RPMC_Read(QLIB_CONTEXT_T* qlibContext, U32* counter, U32 sectionID, U32 offset);
  QLIB_STATUS_T QLIB_RPMC_Inc(QLIB_CONTEXT_T* qlibContext, U32 sectionID, U32 offset);
```
- Added QLIB_IO23_MODE__NONE option to QLIB_IO23_MODE_T ENUM in order to skip configuration of IO23 pins during device configuration:
```C
  typedef enum QLIB_IO23_MODE_T
{
    QLIB_IO23_MODE__LEGACY_WP_HOLD,
    QLIB_IO23_MODE__RESET_IN_OUT,
    QLIB_IO23_MODE__QUAD,
    QLIB_IO23_MODE__NONE, ///< QLIB does not configure IO23 pins.
} QLIB_IO23_MODE_T;
```

### Features
- Add an option to skip pin mux configuration during device configuration.
- Add RPMC implementation and sample code.
- Add features to pyqlib library to allow its usage from local MCU.
- Add optimization to pyqlib dynamic library.
- Update pyqlib to run with Python 3.10.

### Fixes
- Edit of documentation files by technical writer.
- Internal bug fixes


### Performance results

Q32
|                             | NXP-1050<br>Secure OP<br>usec | NXP-1050<br>Secure OP<br>MB/s     | NXP-1050<br>Standard OP<br>usec | NXP-1050<br>Standard OP<br>MB/s | NXP-LPC54005<br>Secure OP<br>usec | NXP-LPC54005<br>Secure OP<br>MB/s | NXP-LPC54005<br>Standard OP<br>usec | NXP-LPC54005<br>Standard OP<br>MB/s |
|-----------------------------|-------------------------------|-----------------------------------|---------------------------------|---------------------------------|-----------------------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| Read SDR Single(256 bytes)  |              91               |               2.813               |                26               |              9.846              |              103                  |               2.485               |                  39                 |                6.564                |
| Read SDR Quad(256 bytes)    |              79               |               3.241               |                15               |              17.066             |              70                   |               3.657               |                  13                 |                19.692               |
| Read DTR Quad(256 bytes)    |              78               |               3.282               |                15               |              17.066             |                                   |                                   |                                     |                                     |
| Write SDR Single(256 bytes) |              883              |               0.290               |               550               |              0.465              |              899                  |               0.284               |                 554                 |                0.462                |
| Write SDR Quad(256 bytes)   |              851              |               0.3                 |               536               |              0.477              |              856                  |               0.299               |                 528                 |                0.484                |

Q128
|                             | NXP-1050<br>Secure OP<br>usec | NXP-1050<br>Secure OP<br>MB/s     | NXP-1050<br>Standard OP<br>usec | NXP-1050<br>Standard OP<br>MB/s | NXP-LPC54005<br>Secure OP<br>usec | NXP-LPC54005<br>Secure OP<br>MB/s | NXP-LPC54005<br>Standard OP<br>usec | NXP-LPC54005<br>Standard OP<br>MB/s |
|-----------------------------|-------------------------------|-----------------------------------|---------------------------------|---------------------------------|-----------------------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| Read SDR Single(256 bytes)  |              90               |               2.844               |                26               |              9.846              |               101                 |               2.534               |                  39                 |                6.564                |
| Read SDR Quad(256 bytes)    |              74               |               3.459               |                15               |              17.066             |               68                  |               3.764               |                  13                 |                19.692               |
| Read DTR Quad(256 bytes)    |              73               |               3.507               |                15               |              17.066             |                                   |                                   |                                     |                                     |
| Write SDR Single(256 bytes) |              799              |               0.320               |               542               |              0.472              |              815                  |               0.314               |                 517                 |                0.495                |
| Write SDR Quad(256 bytes)   |              789              |               0.324               |               532               |              0.481              |              790                  |               0.324               |                 493                 |                0.519                |

Environment used:
- Secure code is running from RAM

- SPI frequency:
  - NXP 1050 - 100 MHz
  - NXP LPC54005 - 60 MHz

- CPU frequency:
  - NXP 1050 - 600 MHz
  - NXP LPC54005 - 180 MHz

- SHA:
  - NXP 1050 - Using HW SHA engine in the SoC
  - NXP LPC54005 - Using HW SHA engine in the SoC

## 0.13.2.0
2022-02-10

**Internal only**

### API

- New API to support RPMC feature:
  ```C
  QLIB_STATUS_T QLIB_RPMC_Read(QLIB_CONTEXT_T* qlibContext, U32* counter, U32 sectionID, U32 offset);
  QLIB_STATUS_T QLIB_RPMC_Inc(QLIB_CONTEXT_T* qlibContext, U32 sectionID, U32 offset);
  ```
- Added QLIB_IO23_MODE__NONE option to QLIB_IO23_MODE_T ENUM in order to skip configuration of IO23 pins during device configuration:
  ```C
  typedef enum QLIB_IO23_MODE_T
{
    QLIB_IO23_MODE__LEGACY_WP_HOLD,
    QLIB_IO23_MODE__RESET_IN_OUT,
    QLIB_IO23_MODE__QUAD,
    QLIB_IO23_MODE__NONE, ///< QLIB does not configure IO23 pins.
} QLIB_IO23_MODE_T;
  ```

### Features
- Add an option to skip pin mux configuration during device configuration.
- Add RPMC implementation and sample code.
- Add features to pyqlib library to allow its usage from local MCU.
- Add optimization to pyqlib dynamic library.
- Update pyqlib to run with Python 3.10.

### Fixes
- Edit of documentation files by technical writer.
- Internal bug fixes

## 0.13.1.1
2022-01-12

**Internal only**

## 0.13.1
2022-01-03

### API

- New API (only for 128Mb) to change the address mode to 3 / 4 bytes addressing:
  ```C
  QLIB_STATUS_T QLIB_SetAddressMode(QLIB_CONTEXT_T* qlibContext, QLIB_STD_ADDR_MODE_T addrMode);
  ```
- New API to read the device configuration:
  ```C
  QLIB_STATUS_T QLIB_GetDeviceConfig(QLIB_CONTEXT_T* qlibContext,
                                     QLIB_WATCHDOG_CONF_T* watchdogDefault,
                                     QLIB_DEVICE_CONF_T*         deviceConf);
  ```
- Added digest and crc attributes to the `QLIB_SECTION_CONFIG_T` struct. This struct is used for section table input in `QLIB_ConfigDevice()` function.
- in 128Mb: change the meaning of parameter `addrMode` in `QLIB_DEVICE_CONF_T` struct which is used in `QLIB_ConfigDevice()`:
  This parameter is used only for setting the power-up address mode in the non-volatile Status Register bit ADP, and does not set the currently used address mode as in the previous release.
  In order  to change the current address-mode (Status Register volatile bit ADS), the `QLIB_SetAddressMode` function should be used.
- If User uses QPI mode and/or 4 bytes address mode (in 128Mb) in XIP, the new function `PLAT_SPI_SetDirectAccessMode(PLAT_SPI_DIRECT_ACCESS_MODE_T* spiMode)` should be implemented to change the fetch command.

### Features

- Full support for 32Mb and 128Mb.
- Add PyQLIB - A python wrapper for QLIB. More details are found in the readme.md file within the pyqlib directory. 
- Section digest and CRC configuration - Using script to calculate the digest and CRC according to the binary file data. In order to use the script:
  - Install the following python packages using `pip install`:
    - pyelftools
    - argh
    - cryptography
  - Find out the platform objtool - a tool which read/writes to the binary file. We use this tool to convert the axf file to bin file.
  - Use the following command line:
  ```batch
  python.exe run_section_integrity.py --axf_filename <the binary file that will be changed to include the crc and digest values> --qconf_struct_name <Symbol name of QCONF_T struct> --objcopy_path <Path of objcopy executable> --padding <padding value> --hash <hash algorithm - sha256>
  ```
- `QLIB_ConfigDevice` - Configure the CRC and digest of a section.
- 128Mb - Support 4 bytes addressing in XIP with the use of platform function `PLAT_SPI_SetDirectAccessMode`
- Samples - Changed section 1 in the samples configuration to be authenticated plain access and add test for authenticated PA in secure storage sample
- Support user-defined value for setting the number of dummy-clocks in QPI fast read commands:
  User may define `QLIB_QPI_READ_DUMMY_CYCLES` to either 4/6/8 dummy clocks which QLIB sets in Set Read Parameters command.
  If this definition is missing in QPI mode, QLIB will use a default value of 8 which might affect performance. 
  Therefore it is recommended to set this value according to user platform. 
- Add optional definitions for faster QLIB initialization:
  - If QLIB is initialized after flash power up, it is optional to define `QLIB_INIT_AFTER_Q2_POWER_UP` which let QLIB assume the W77Q is 
    in SPI mode, power-up mode and not suspended.
  - User should define `QLIB_INIT_BUS_MODE` if the W77Q current SPI mode is known. Otherwise, QLIB device initialization will detect 
    automatically if the flash is in SPI or QPI mode.
    
### Fixes

- Fix watchdog_trigger in QPI mode.
- Fix dynamic change between SPI and QPI modes in XIP, by use of platform function `PLAT_SPI_SetDirectAccessMode`

### Performance results

Q32
|                             | NXP-1050<br>Secure OP<br>usec | NXP-1050<br>Secure OP<br>MB/s     | NXP-1050<br>Standard OP<br>usec | NXP-1050<br>Standard OP<br>MB/s | NXP-LPC54005<br>Secure OP<br>usec | NXP-LPC54005<br>Secure OP<br>MB/s | NXP-LPC54005<br>Standard OP<br>usec | NXP-LPC54005<br>Standard OP<br>MB/s |
|-----------------------------|-------------------------------|-----------------------------------|---------------------------------|---------------------------------|-----------------------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| Read SDR Single(256 bytes)  |              89               |               2.876               |                26               |              9.846              |              103                  |               2.485               |                  39                 |                6.564                |
| Read SDR Quad(256 bytes)    |              76               |               3.368               |                15               |              17.066             |              70                   |               3.657               |                  13                 |                19.692               |
| Read DTR Quad(256 bytes)    |              76               |               3.368               |                15               |              17.066             |                                   |                                   |                                     |                                     |
| Write SDR Single(256 bytes) |              880              |               0.290               |               549               |              0.466              |              899                  |               0.284               |                 554                 |                0.462                |
| Write SDR Quad(256 bytes)   |              851              |               0.3                 |               536               |              0.477              |              856                  |               0.299               |                 528                 |                0.484                |

Q128
|                             | NXP-1050<br>Secure OP<br>usec | NXP-1050<br>Secure OP<br>MB/s     | NXP-1050<br>Standard OP<br>usec | NXP-1050<br>Standard OP<br>MB/s | NXP-LPC54005<br>Secure OP<br>usec | NXP-LPC54005<br>Secure OP<br>MB/s | NXP-LPC54005<br>Standard OP<br>usec | NXP-LPC54005<br>Standard OP<br>MB/s |
|-----------------------------|-------------------------------|-----------------------------------|---------------------------------|---------------------------------|-----------------------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| Read SDR Single(256 bytes)  |              87               |               2.942               |                26               |              9.846              |               101                 |               2.534               |                  39                 |                6.564                |
| Read SDR Quad(256 bytes)    |              70               |               3.657               |                15               |              17.066             |               68                  |               3.764               |                  13                 |                19.692               |
| Read DTR Quad(256 bytes)    |              72               |               3.555               |                15               |              17.066             |                                   |                                   |                                     |                                     |
| Write SDR Single(256 bytes) |              798              |               0.32                |               543               |              0.471              |              814                  |               0.314               |                 517                 |                0.495                |
| Write SDR Quad(256 bytes)   |              789              |               0.324               |               533               |              0.48               |              790                  |               0.324               |                 493                 |                0.519                |

Environment used:
- Secure code is running from RAM

- SPI frequency:
  - NXP 1050 - 100 MHz
  - NXP LPC54005 - 60 MHz

- CPU frequency:
  - NXP 1050 - 600 MHz
  - NXP LPC54005 - 180 MHz

- SHA:
  - NXP 1050 - Using HW SHA engine in the SoC
  - NXP LPC54005 - Using HW SHA engine in the SoC

## 0.13.0
2022-01-03

**Internal only**

## 0.12.0
2021-10-04

### API

API changes of QLIB for the 128Mb flash:
- `QLIB_ConfigDevice` 
  - Added `fallbackEn` field to the watchdog structure
  - Added to the device configuration structure the following fields:
    -  Standard address mode in the standard address size structure
    -  RNG plain access enabled
    -  DEVCFG CTAG mode

API changes for all QLIB flavors:
- `QLIB_GetVersion` - Added QLIB target information in addition to the QLIB version:
  - Flash size
  - Single/multi-die
  - Revision (A, B, C, etc)
- `QLIB_GetHWVersion` - Added the following fields to the HW version structure:
  - flashSize
  - Single/multi-die
  - Secure/Standard

### Features

- Support extended address bits in 3 bytes address mode
- Support AWDT Fallback feature for w77q128
- Support CTAG mode value of 1 for w77q128
- Add RNG plain access configuration for w77q128

### Fixes

- Disable secure commands DTR in QLIB for w77q128, since it is not supported
- sample watchdog: authenticated watchdog configuration requires open session on currently configured section and not the new one
- Internal bug fixes

### Known Issues

- QLIB_Watchdog_Trigger function is not supported in QPI mode

## 0.11.2
2021-04-08

### API
- Add `QLIB_GetResetStatus` function to read the last reset reason (status). New function - **Backwards compatible**.
- Add `QLIB_GetHwVersion` function to read the flash version. New function - **Backwards compatible**.
- Change `QLIB_GetId` to include only the unique ID. **Not Backwards compatible**.
- `QLIB_ConfigDevice`: Change `QLIB_DEVICE_CONF_T` parameter structure to include standard address size configuration option. **Not backwards compatible**.
- `QLIB_IsMaintenanceNeeded` deprecated and added `QLIB_GetNotifications` instead in order to return more information from W77Q. **Not backwards compatible**.
- `CORE_RESET`: changed to a function rather than macro. Need to change the implementation in qlib_platform.c. **Not backwards compatible**.
- `PLAT_SHA`: changed to `PLAT_HASH` as QLIB now support multiple hash functions. **Not backwards compatible**.

### Features

- QCONF: Change QCONF to support configuration of sections with CRC and Digest when there is no direct flash access.
- Change samples to use different keys values for restricted and full access key of each section

### Fixes

- `QLIB_Format` - Added SW reset after format
- After review of the Security flows described in the HW spec - adjust QLIB to behave as described in the Security flows
- Add W77Q128 support
- Updated QLIB manual documentation
  - Add optimization section to quick start guide
  - `QLIB_ConfigSection` documentation now states that permission access policy of section 0 and 7 shall be identical
- Authenticated PA revoke does not close the active session
- Several bug fixes

### Performance results

|                             | NXP-1050<br>Secure OP<br>usec | NXP-1050<br>Secure OP<br>MB/s     | NXP-1050<br>Standard OP<br>usec | NXP-1050<br>Standard OP<br>MB/s | NXP-LPC54005<br>Secure OP<br>usec | NXP-LPC54005<br>Secure OP<br>MB/s | NXP-LPC54005<br>Standard OP<br>usec | NXP-LPC54005<br>Standard OP<br>MB/s |
|-----------------------------|-------------------------------|-----------------------------------|---------------------------------|---------------------------------|-----------------------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| Read SDR Single(256 bytes)  |              75               |               3.413               |                25               |              10.240             |               84                  |               3.048               |                  27                 |                9.481                |
| Read SDR Quad(256 bytes)    |              62               |               4.129               |                14               |              18.286             |               63                  |               4.063               |                  9                  |                28.444               |
| Read DTR Quad(256 bytes)    |              62               |               4.129               |                14               |              18.286             |                                   |                                   |                                     |                                     |
| Write SDR Single(256 bytes) |              863              |               0.297               |               550               |              0.465              |              826                  |               0.310               |                 508                 |                0.504                |
| Write SDR Quad(256 bytes)   |              843              |               0.304               |               537               |              0.477              |              801                  |               0.320               |                 492                 |                0.520                |
| Erase Sector Single         |             74095             |               0.003               |              72200              |              0.004              |             68900                 |               0.004               |                68881                |                0.004                |
| Erase 32K Block Single      |             136525            |               0.002               |              136833             |              0.002              |             123547                |               0.002               |                130870               |                0.002                |
| Erase 64K Block Single      |             21340             |               0.012               |              204772             |              0.001              |             198274                |               0.001               |                198860               |                0.001                |
| Erase Sector Quad           |             72059             |               0.004               |              72154              |              0.004              |             70627                 |               0.004               |                68812                |                0.004                |
| Erase 32K Block Quad        |             136345            |               0.002               |              136763             |              0.002              |             129889                |               0.002               |                135625               |                0.002                |
| Erase 64K Block Quad        |             220932            |               0.001               |              214004             |              0.001              |             206956                |               0.001               |                183414               |                0.001                |

Environment used:
- Secure code is running from RAM

- SPI frequency:
  - NXP 1050 - 100 MHz
  - NXP LPC54005 - 90 MHz

- CPU frequency:
  - NXP 1050 - 600 MHz
  - NXP LPC54005 - 180 MHz

- SHA:
  - NXP 1050 - Using HW SHA engine in the SoC
  - NXP LPC54005 - Using HW SHA engine in the SoC

## 0.11.1
2021-04-08

**Internal only**

## 0.11.0
2021-04-08

**Internal only**

## 0.10.1
2021-01-12

### Performance results
**Same as 0.10.0 below**

### Fixes
- Double getSSR in dual (1_1_2) mode fix

## 0.10.0
2021-01-07

### Performance results

|                             | NXP-1050<br>Secure OP<br>usec | NXP-1050<br>Secure OP<br>MB/s     | NXP-1050<br>Standard OP<br>usec | NXP-1050<br>Standard OP<br>MB/s | NXP-LPC54005<br>Secure OP<br>usec | NXP-LPC54005<br>Secure OP<br>MB/s | NXP-LPC54005<br>Standard OP<br>usec | NXP-LPC54005<br>Standard OP<br>MB/s |
|-----------------------------|-------------------------------|-----------------------------------|---------------------------------|---------------------------------|-----------------------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| Read SDR Single(256 bytes)  |              105              |               2.438               |                27               |              9.481              |               94                  |               2.723               |                  28                 |                9.143                |
| Read SDR Quad(256 bytes)    |              75               |               3.413               |                14               |              18.286             |               62                  |               4.129               |                  9                  |                28.444               |
| Read DTR Quad(256 bytes)    |              90               |               2.844               |                16               |              16.000             |                                   |                                   |                                     |                                     |
| Write SDR Single(256 bytes) |              889              |               0.288               |               555               |              0.461              |              867                  |               0.295               |                 544                 |                0.471                |
| Write SDR Quad(256 bytes)   |              851              |               0.301               |               539               |              0.475              |              826                  |               0.310               |                 524                 |                0.489                |
| Erase Sector Single         |             64337             |               0.004               |              64337              |              0.004              |             60001                 |               0.004               |                59716                |                0.004                |
| Erase 32K Block Single      |             137732            |               0.002               |              137218             |              0.002              |             131165                |               0.002               |                133566               |                0.002                |
| Erase 64K Block Single      |             223840            |               0.001               |              223553             |              0.001              |             200433                |               0.001               |                205713               |                0.001                |
| Erase Sector Quad           |             67411             |               0.004               |              65808              |              0.004              |             62242                 |               0.004               |                62197                |                0.004                |
| Erase 32K Block Quad        |             136132            |               0.002               |              135846             |              0.002              |             145464                |               0.002               |                139700               |                0.002                |
| Erase 64K Block Quad        |             208681            |               0.001               |              208474             |              0.001              |             225029                |               0.001               |                215920               |                0.001                |

Environment used:
- Secure code is running from RAM

- SPI frequency:
  - NXP 1050 - 100 MHz
  - NXP LPC54005 - 90 MHz

- CPU frequency:
  - NXP 1050 - 600 MHz
  - NXP LPC54005 - 180 MHz

- SHA:
  - NXP 1050 - Using HW SHA engine in the SoC
  - NXP LPC54005 - Using HW SHA engine in the SoC

### Features
- Allow key_SECRET to be NULL

### Other changes
- Additional Secure Read performance enhancements for NXP platform
- Double getSSR in single(1_1_1) mode fix


## 0.9.1
2020-12-28

### Performance results

|                             | NXP-1050<br>Secure OP<br>usec | NXP-1050<br>Secure OP<br>MB/s     | NXP-1050<br>Standard OP<br>usec | NXP-1050<br>Standard OP<br>MB/s | NXP-LPC54005<br>Secure OP<br>usec | NXP-LPC54005<br>Secure OP<br>MB/s | NXP-LPC54005<br>Standard OP<br>usec | NXP-LPC54005<br>Standard OP<br>MB/s |
|-----------------------------|-------------------------------|-----------------------------------|---------------------------------|---------------------------------|-----------------------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| Read SDR Single(256 bytes)  |              88               |               2.909               |                25               |              10.240             |               82                  |               3.122               |                  26                 |                9.846                |
| Read SDR Quad(256 bytes)    |              74               |               3.459               |                14               |              18.286             |               61                  |               4.197               |                  9                  |                28.444               |
| Read DTR Quad(256 bytes)    |              90               |               2.844               |                16               |              16.000             |                                   |                                   |                                     |                                     |
| Write SDR Single(256 bytes) |              886              |               0.289               |               561               |              0.456              |              902                  |               0.284               |                 577                 |                0.444                |
| Write SDR Quad(256 bytes)   |              865              |               0.296               |               548               |              0.467              |              875                  |               0.293               |                 555                 |                0.461                |
| Erase Sector Single         |             41001             |               0.006               |              43862              |              0.006              |             48540                 |               0.005               |                50192                |                0.005                |
| Erase 32K Block Single      |             97457             |               0.003               |              98754              |              0.003              |             102092                |               0.003               |                100887               |                0.003                |
| Erase 64K Block Single      |             135307            |               0.002               |              170589             |              0.002              |             171214                |               0.001               |                181329               |                0.001                |
| Erase Sector Quad           |             43769             |               0.006               |              42366              |              0.006              |             46995                 |               0.005               |                49774                |                0.005                |
| Erase 32K Block Quad        |             114773            |               0.002               |              98026              |              0.003              |             101788                |               0.003               |                101151               |                0.003                |
| Erase 64K Block Quad        |             183457            |               0.001               |              185585             |              0.001              |             169927                |               0.002               |                169861               |                0.002                |

Environment used:
- Secure code is running from RAM

- SPI frequency:
  - NXP 1050 - 100 MHz
  - NXP LPC54005 - 90 MHz

- CPU frequency:
  - NXP 1050 - 600 MHz
  - NXP LPC54005 - 180 MHz

- SHA:
  - NXP 1050 - Using HW SHA engine in the SoC
  - NXP LPC54005 - Using HW SHA engine in the SoC
  
### Fixes

- Update the WD LF-oscillator calibration value
- Remove multi transaction optimization from QLIB_write

## 0.9.0
2020-12-21

### Performance results

|                             | NXP-1050<br>Secure OP<br>usec | NXP-1050<br>Secure OP<br>MB/s     | NXP-1050<br>Standard OP<br>usec | NXP-1050<br>Standard OP<br>MB/s | NXP-LPC54005<br>Secure OP<br>usec | NXP-LPC54005<br>Secure OP<br>MB/s | NXP-LPC54005<br>Standard OP<br>usec | NXP-LPC54005<br>Standard OP<br>MB/s |
|-----------------------------|-------------------------------|-----------------------------------|---------------------------------|---------------------------------|-----------------------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| Read SDR Single(256 bytes)  |              88               |               2.909               |                25               |              10.240             |               82                  |               3.122               |                  27                 |                9.481                |
| Read SDR Quad(256 bytes)    |              74               |               3.459               |                14               |              18.286             |               61                  |               4.197               |                  9                  |                28.444               |
| Read DTR Quad(256 bytes)    |              90               |               2.844               |                16               |              16.000             |                                   |                                   |                                     |                                     |
| Write SDR Single(256 bytes) |              886              |               0.289               |               561               |              0.456              |              863                  |               0.297               |                 554                 |                0.462                |
| Write SDR Quad(256 bytes)   |              858              |               0.298               |               548               |              0.467              |              839                  |               0.305               |                 536                 |                0.478                |
| Erase Sector Single         |             43880             |               0.006               |              43921              |              0.006              |             43486                 |               0.006               |                42093                |                0.006                |
| Erase 32K Block Single      |             91379             |               0.003               |              92057              |              0.003              |             91105                 |               0.003               |                87137                |                0.003                |
| Erase 64K Block Single      |             175474            |               0.001               |              177478             |              0.001              |             157901                |               0.002               |                158800               |                0.002                |
| Erase Sector Quad           |             45394             |               0.006               |              45419              |              0.006              |             42017                 |               0.006               |                42020                |                0.006                |
| Erase 32K Block Quad        |             86783             |               0.003               |              87732              |              0.003              |             90503                 |               0.003               |                91089                |                0.003                |
| Erase 64K Block Quad        |             191827            |               0.001               |              177376             |              0.001              |             156319                |               0.002               |                174500               |                0.001                |

Environment used:
- Secure code is running from RAM

- SPI frequency:
  - NXP 1050 - 100 MHz			
  - NXP LPC54005 - 90 MHz			

- CPU frequency:
  - NXP 1050 - 600 MHz		
  - NXP LPC54005 - 180 MHz			

- SHA:
  - NXP 1050 - Using HW SHA engine in the SoC			
  - NXP LPC54005 - Using HW SHA engine in the SoC
  
### API

- Added the following API functions:
  - `QLIB_STATUS_T QLIB_AuthPlainAccess_Grant(QLIB_CONTEXT_T* qlibContext, U32 sectionID)`
  - `QLIB_STATUS_T QLIB_AuthPlainAccess_Revoke(QLIB_CONTEXT_T* qlibContext, U32 sectionID)`
  - `QLIB_STATUS_T QLIB_PlainAccessEnable(QLIB_CONTEXT_T* qlibContext, U32 sectionID)`
  - `QLIB_STATUS_T QLIB_CalcCDI(QLIB_CONTEXT_T* qlibContext, _256BIT nextCdi, _256BIT prevCdi, U32 sectionId)`
  - `QLIB_STATUS_T QLIB_Watchdog_ConfigGet(QLIB_CONTEXT_T* qlibContext, QLIB_WATCHDOG_CONF_T* watchdogCFG)`
  - `QLIB_STATUS_T QLIB_SetActiveChip(QLIB_CONTEXT_T* qlibContext, U8 die)`  

- Removed the following API functions:
  - `QLIB_ConfigSectionTable`
  - `QLIB_ConfigInterface`

- Renamed the following API functions:
  - `QLIB_GetSectionConfigurations` to `QLIB_GetSectionConfiguration`
  - `QLIB_Watchdog_Config` to `QLIB_Watchdog_ConfigSet`

- Added parameters to the following API functions:
  - `QLIB_Watchdog_Get` - `U32* ticsResidue`

### Features

- LS bits randomization in Read/Write/Erase secure commands
- Added SW Get_NONCE, and SHA to the platform
- QCONF supports 64 bit core address
- Change chip name from w77m_w25q256jw to w77m32i
- Performance improvements (INTRLV_EN, resp_ready, multi transaction command, aligned read, memcpy optimizations)


### Fixes

- errata SEC-5,SSR-5 workarounds
- disable checksumIntegrity from the QCONF configuration in the sample code
- WD calibration has overwritten at the follow POR
- enable Speculative Cypher Key Generation
- bug in SRD optimization that makes MC get out of sync
- GET_SSR is forbidden in power-down mode
- set active chip to die 0 on connect/disconnect for server synch, and check connection before STD commands

### Other changes

- adding documentation for QLIB_ConfigSection limitations when XIP 

## 0.8.0
2020-10-20


### API changes

- adding API to grant and revoke authenticated plain access 

### Features
- multi-die support     

### Fixes

- **performance:** adding inline functions, optimization for multi-transaction reads/writes
- **code:** fix bug in QLIB_SAMPLE_WatchDogCalibrate()

### Other changes
- Added documentation for security flows

## 0.7.0
2020-08-26

### Performance results

|                             | NXP-1050<br>Secure OP<br>usec | NXP-1050<br>Secure OP<br>MB/s | NXP-1050<br>Standard OP<br>usec | NXP-1050<br>Standard OP<br>MB/s | NXP-LPC54005<br>Secure OP<br>usec | NXP-LPC54005<br>Secure OP<br>MB/s | NXP-LPC54005<br>Standard OP<br>usec | NXP-LPC54005<br>Standard OP<br>MB/s |
|-----------------------------|-------------------------------|-----------------------------------|---------------------------------|---------------------------------|-------------------------------|-----------------------------------|-------------------------------------|-------------------------------------|
| Read SDR Single(256 bytes)  |              156              |               1.641               |                28               |              9.143              |              114              |               2.246               |                  25                 |                10.24                |
| Read SDR Quad(256 bytes)    |              146              |               1.753               |                22               |              11.636             |               95              |               2.695               |                  9                  |                28.444               |
| Read DTR Quad(256 bytes)    |              146              |               1.753               |                22               |              11.636             |                               |                                   |                                     |                                     |
| Write SDR Single(256 bytes) |              882              |                0.29               |               517               |              0.495              |              841              |               0.304               |                 501                 |                0.511                |
| Write SDR Quad(256 bytes)   |              887              |               0.292               |               506               |              0.506              |              814              |               0.314               |                 485                 |                0.528                |
| Erase Sector Single         |             51611             |               0.005               |              50452              |              0.005              |             49864             |               0.005               |                49857                |                0.005                |
| Erase 32K Block Single      |             100265            |               0.003               |              102819             |              0.002              |             97214             |               0.003               |                97257                |                0.003                |
| Erase 64K Block Single      |             164007            |               0.002               |              170082             |              0.002              |             174368            |               0.001               |                169074               |                0.002                |
| Erase Sector Quad           |             51612             |               0.005               |              52772              |              0.005              |             51005             |               0.005               |                50985                |                0.005                |
| Erase 32K Block Quad        |             102404            |               0.002               |              100316             |              0.003              |             97068             |               0.003               |                99358                |                0.003                |
| Erase 64K Block Quad        |             173893            |               0.001               |              169516             |              0.002              |             162729            |               0.002               |                163204               |                0.002                |

Environment used:
- Secure code is running from RAM

- SPI frequency:
  - NXP 1050 - 100 MHz			
  - NXP LPC54005 - 90 MHz			

- CPU frequency:
  - NXP 1050 - 600 MHz		
  - NXP LPC54005 - 180 MHz			

- SHA:
  - NXP 1050 - Using HW SHA engine in the SoC			
  - NXP LPC54005 - Using HW SHA engine in the SoC	

### Features

- **code:** Move QPI code under `QLIB_SUPPORT_QPI` definition.
- **performance:** Improve performance by adding "idle task" feature to the TM layer. This allows to perform tasks in parallel to the flash operation, while the flash is busy.

### Fixes

- **performance:** Improve performance by:
  - Set reserved bit (INTRLV_EN) to 0 in the device configuration function
  - Improving `QLIB_CRYPTO` functions
  - Create `QLIB_SEC_READ_DATA_T` type which reduce the number of memcpy used
  - Remove the "get SSR" after "OP2" of every secure command as "OP2" cannot trigger any security related errors
  - Error masks now include only the error bits and bypass all the specific bits check in `QLIB_CMD_PROC__checkLastSsrErrors()` if no error is found
- **samples:**
  - WD calibration, - fix a bug where the calibration value did not update the permanent WD configuration register. Therefore WD calibration has overwritten at the follow POR
  - Enable Speculative Cipher Key Generation for better performance
  - Disable `checksumIntegrity` from the QCONF configuration in the sample code
- **code:** add support for 64Bit core/address to QCONF
- **code:** fix bug in `QLIB_InitDevice()` to prevent from the function to fail
- **documentation:** add `QLIB_SUPPORT_QPI` definition to quick_start.md

### Known Issues

- not support QPI while executing from flash (XIP)
- suspend/resume mechanism is not fully supported

## 0.6.1
2020-08-04

### Fixes

- **qconf:** Define `QCONF_NO_DIRECT_FLASH_ACCESS` to allows QCONF to run when there is no direct access to the flash. This mode has two effects:
  - The configuration structure will not be erased (keys included) 
  - Integrity protected sections are not supported

## 0.6.0
2020-06-25

### API changes

- remove INTRLV_EN configuration from QLIB_DEVICE_CONF_T structure passes to API function QLIB_ConfigDevice.
- QLIB_GetSectionConfigurations returns size sero for disabled section 
- replace QLIB_BUS_MODE_T and DTR with QLIB_BUS_FORMAT_T in QLIB_InitDevice, QLIB_SetInterface, QLIB_ConfigInterface APIs
- replace key pointers arrays restrictedKeys and fullAccessKeys in QLIB_ConfigDevice API with key arrays
- replace resetResp pointer in QLIB_DEVICE_CONF_T structure passes to API function QLIB_ConfigDevice resetResp structure.
- Now QLIB_ConfigDevice() allows to receive valid keys & SUID ans not return error if keys already provisioned

### Features

- **qconf:** add qconf code, samples and documentation

### Fixes

- **code:** Allow to execute "SET_SCR/SWAP" based APIs from XIP
- **documentation:** add license agreement text file
- **qpi:** fix reset_flash command in QPI mode
- **documentation:** Updating to correct flow-chart
- **documentation:** added a list of macros that must be linked to RAM


## 0.5.2
2020-06-04

### Fixes

- **documentation:** added software stack drawing and RAM usage indication 

## 0.5.1
2020-06-01

### Fixes

- **documentation:** add quick start page
- **documentation:** added interface variables boundaries indication in qlib.h
- **samples:** update sample code for fw update and watchdog
 

## 0.5.0
2020-05-26

### API changes

- remove the API function QLIB_EraseChip().
- add "eraseDataOnly" parameter to QLIB_Format() that if TRUE then SERASE (Secure Erase) command is used to securely erase only the data of all sections, configurations and keys do not change in this case.
- standard QLIB operations return specific error instead of general QLIB_STATUS__DEVICE_ERR

### Features

- **documentation:** updated QLIB documentation

### Fixes

- **code:** improve errors return from QLIB_Erase API
- **code:** fix the QPI support for secure commands

### Known Issues
- suspend/resume mechanism is not fully supported

## 0.4.0
2020-05-13

### Features

- **api:** add QLIB_SetInterface API to change bus format without changing the flash configurations
- **samples:** add sample code for: device configuration, fw update, secure storage, authenticated watchdog
- **doc:** Adding improved doxygen based user-guide (preliminary version)

### Known Issues
- suspend/resume mechanism is not fully supported
- QPI mode is not supported
- Erasing rollback protected section with CHIP_ERASE or ERASE_SECT_PA commands erases the active part instead of the inactive part of the section

## 0.3.0
2020-04-30

### Features

- **configuration** QLIB_SEC_ONLY pre-compile configuration to suppress all legacy support from qlib
- **api** added QLIB_GetStatus API
- **code** allows to config the buss interface after QLIB_InitLib and before QLIB_InitDevice

### Fixes

- **documentation:**
- **code** improve QLIB_STD_autoSense_L - check for single format first and replace getId command with more efficient get JEDEC command
- **code** do not reset the flash at initDevice, instead resume any existing erase/write and wait for the device to be ready
- **code** remove QLIB_STD_CheckDeviceIsBusy_L before STD commands
- **code** allows QLIB_TM_Standard accept NULL status pointer

## 0.2.0
2020-04-22

### Features

- **api:** Add expire parameter to QLIB_Watchdog_Get API
- **sec:** Add SSR state field definitions
- **all:** Add API to use logical address instead of sectionID/offset pair
- **api:** Add support for secure/non-secure Section Erase

### Fixes

- **sim:** Fix flash file handling
- **deliverables:** Add src directory, Add PDF document and optimize doxygen
- **documentation:** Add license information
- **doc:** Fix doxygen errors
- **suspend/resume:** Fix suspend/resume state checks
- **all:** Fix packed structures handling
- **sec:** Read watchdog configuration during Init
- **xip:** Do not disable quad mode to allows for quad XIP

## 0.1.0
2020-04-07

### First released Version  
