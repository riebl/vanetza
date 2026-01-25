# ETSI ITS ASN.1

The ASN.1 files in this directory are a slightly patched subset of the files published by ETSI for ITS Release 2.
You can find the original files on [ETSI Forge](https://forge.etsi.org/rep/ITS/asn1). Our changes are documented below.
These files are distributed under a permissive license:

> Copyright 2019 ETSI
>
> Redistribution and use in source and binary forms, with or without 
> modification, are permitted provided that the following conditions are met:
> 1. Redistributions of source code must retain the above copyright notice, 
>    this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice, 
>    this list of conditions and the following disclaimer in the documentation 
>    and/or other materials provided with the distribution.
> 3. Neither the name of the copyright holder nor the names of its contributors 
>    may be used to endorse or promote products derived from this software without 
>    specific prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
> ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
> WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
> IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
> INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
> BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
> DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
> LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
> OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
> OF THE POSSIBILITY OF SUCH DAMAGE.


# Changes

## CDD

Removed obsolete `ActionID` and `StationID` data elements. The generated file names clash with those of `ActionId` and `StationId` on case-insensitive filesystems.

## CPM

Updated CDD imports.

## VAM

Updated CDD imports.
