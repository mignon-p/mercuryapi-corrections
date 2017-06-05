This repository is a collection of small patches that I (Patrick
Pelletier) have made to ThingMagic's Mercury API.  I have submitted my
patches to ThingMagic, but I don't know when or whether they'll be
included in the official release, so I'm also making them available
here.

This repo is currently up-to-date with [mercuryapi-1.29.3.34.zip][1].
The repo only contains the files from the `c/src/api/` directory of
the Mercury API zipfile.

Each topic is on a separate branch, and then they have all been merged
together on master.  Here are the topic branches:

`eintr` - This retries the `select()` operation when it returns
`EINTR`.  This is always good practice, but it seemed to be necessary
in my situation to avoid failing with a timeout.  There are probably
plenty of other places in the API where this should be done, too.

`extern` - This fixes a problem I ran into with
`isSecureAccessEnabled` being multiply defined, when compiling with
cabal.  (Strangely, doesn't happen when using ThingMagic's Makefile.)

`host-c-library` - The build failed when `TMR_USE_HOST_C_LIBRARY` was
defined.  This fixes that.

`infinite-loop` - This avoids an infinite loop that I ran into, when
somehow `readOffSet` was 142, and `dataLength` was 128.  Not sure how
that happened, and it probably indicates another bug, but at least
this fix prevents going into an infinite loop in that situation.

`metadataflag-size` - `paramSet()` treated `TMR_PARAM_METADATAFLAG` as
`TMR_TRD_MetadataFlag`, while `paramGet()` treated
`TMR_PARAM_METADATAFLAG` as `uint16_t`.  Since
`sizeof(TMR_TRD_MetadataFlag)` is 4 but `sizeof(uint16_t)` is 2, the
sizes didn't match.  This patch fixes `paramGet()` to also treat it as
`TMR_TRD_MetadataFlag`.

`mingw-dword-pointer` - Fixes a compiler warning about `warning:
passing argument 4 of 'ReadFile' from incompatible pointer type
[-Wincompatible-pointer-types]`.  Somehow the warning was getting
treated as an error on Appveyor.

`mingw-snprintf` - Fixes a problem I ran into on MinGW, where
`sprintf_s()` doesn't seem to work properly, but `snprintf()` does
work properly.

`typos` - This just fixes a bunch of small typos I found.

`windows-time` - On Windows, `tmr_gettime_low()` and
`tmr_gettime_high()` were returning the number of 100-nanosecond units
since 1/1/1601, rather than the number of milliseconds since 1/1/1970.
This caused the `timestampLow` and `timestampHigh` fields of
`TMR_TagReadData` to be populated incorrectly.  This patch fixes that
problem.

[1]: http://www.thingmagic.com/images/Downloads/software/mercuryapi-1.29.3.34.zip
