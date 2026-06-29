# Heap buffer overflow in bundled OpenJPEG J2K decoder due to missing tile‑part index bounds check

## Overview

A heap‑buffer‑overflow vulnerability exists in the OpenJPEG JPEG2000 decoder bundled with MuPDF. Processing a malicious PDF containing a malformed JPX/JPEG2000 image triggers an out‑of‑bounds write to a heap‑allocated array due to missing index boundary validation, leading to application crash and potential remote code execution.

## Steps to Reproduce

1. Clone the mupdf repository and build it refer to oss-fuzz.

```
export CC=clang \
    CXX=clang++ \
    CFLAGS='-fsanitize=address -O0 -g' \
    CXXFLAGS='-fsanitize=address -O0 -g' \
    LIB_FUZZING_ENGINE='-fsanitize=fuzzer'
```

2.Run the PoC using pdf_fuzzer:

The PoC is provided as a zip archive. After extracting, run:

```
./pdf_fuzzer ./poc
```

## Actual Results

MuPDF crashes immediately with an AddressSanitizer heap‑buffer‑overflow error at `thirdparty/openjpeg/src/lib/openjp2/j2k.c:5086` during JPX tile‑part parsing.

ASan report confirms an 8‑byte out‑of‑bounds write 8 bytes after a 40‑byte allocated heap region.

## Expected Results

MuPDF should safely reject the malformed JPX image input with an error message, without crashing or writing out‑of‑bounds heap memory.

## Build Date & Hardware

Latest git main branch build on Linux x86_64.

## Additional Builds and Platforms

Likely reproducible on all supported MuPDF platforms (Linux, Windows, macOS).

## Additional Information

### Root Cause

In `j2k.c` line 5086, the code accesses the `tp_index` heap‑allocated array using the variable `l_current_tile_part` without validating the index bounds:

1. Each `opj_tp_index_t` struct is **24 bytes** (`sizeof(opj_tp_index_t) = 0x18`).
2. The `tp_index` array is allocated with only **40 bytes**, which can only store **one valid element (index 0)**.
3. Malformed JPX input forces `l_current_tile_part = 1`, accessing the second element beyond allocated heap memory and triggering an out‑of‑bounds write.

### Debug Verification (GDB/Pwndbg Evidence)

- Confirmed `l_current_tile_part = 1` at crash breakpoint `j2k.c:5086`.
- Confirmed `sizeof(opj_tp_index_t) = 24` bytes.
- 2 elements require 48 bytes, exceeding the 40‑byte allocated heap buffer, mathematically proving out‑of‑bounds access.

### Fix Suggestion

Add index bounds checking before accessing `tp_index[l_current_tile_part]` at line 5086 in `j2k.c`:

```
if (l_current_tile_part >= 1) {
    opj_event_msg(p_manager, EVT_ERROR, "Tile part index out of bounds");
    return OPJ_FALSE;
}
```

### Impact

A remote attacker can craft a malicious PDF file. When opened by MuPDF, the vulnerability causes denial‑of‑service (application crash), and may allow arbitrary code execution under specific memory layout conditions.



### ASAN report:
```
=================================================================
==100451==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x504000000ac0 at pc 0x56132aa2b4bd bp 0x7ffd4dd1b100 sp 0x7ffd4dd1b0f8
WRITE of size 8 at 0x504000000ac0 thread T0
    #0 0x56132aa2b4bc in fz_opj_j2k_read_sod /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:5086:13
    #1 0x56132aa273bc in fz_opj_j2k_read_tile_header /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:9912:19
    #2 0x56132aa5e5d3 in fz_opj_j2k_decode_tiles /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:12079:19
    #3 0x56132aa24328 in fz_opj_j2k_exec /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:9181:33
    #4 0x56132aa379e0 in fz_opj_j2k_decode /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:12425:11
    #5 0x56132a4c13d0 in fz_opj_decode /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/openjpeg.c:526:16
    #6 0x5613299de056 in jpx_read_image /home/hexijie/fuzz/project/mupdf/source/fitz/load-jpx.c:472:8
    #7 0x5613299dda60 in fz_load_jpx /home/hexijie/fuzz/project/mupdf/source/fitz/load-jpx.c:653:9
    #8 0x5613299a65e5 in compressed_image_get_pixmap /home/hexijie/fuzz/project/mupdf/source/fitz/image.c:843:10
    #9 0x5613299a1689 in fz_get_pixmap_from_image /home/hexijie/fuzz/project/mupdf/source/fitz/image.c:1102:9
    #10 0x56132990211c in fz_draw_fill_image /home/hexijie/fuzz/project/mupdf/source/fitz/draw-device.c:1903:11
    #11 0x561329bb6e29 in fz_fill_image /home/hexijie/fuzz/project/mupdf/source/fitz/device.c:384:4
    #12 0x561329e4ac67 in pdf_show_image_imp /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-op-run.c:879:3
    #13 0x561329e4a618 in pdf_show_image /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-op-run.c:943:4
    #14 0x561329e33f90 in pdf_run_Do_image /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-op-run.c:3229:2
    #15 0x561329db1fc2 in pdf_process_Do /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1081:5
    #16 0x561329dae1df in pdf_process_keyword /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1511:19
    #17 0x561329da48d9 in pdf_process_stream /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1686:6
    #18 0x561329da2bff in pdf_process_raw_contents /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1826:3
    #19 0x561329da50db in pdf_process_contents /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1849:3
    #20 0x561329e73487 in pdf_run_page_contents_with_usage_imp /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-run.c:187:3
    #21 0x561329e7241c in pdf_run_page_contents_with_usage /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-run.c:224:3
    #22 0x561329e738e4 in pdf_run_page_contents /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-run.c:239:2
    #23 0x561329e5ff9d in pdf_run_page_contents_imp /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-page.c:1124:2
    #24 0x5613298eb78a in fz_run_page_contents /home/hexijie/fuzz/project/mupdf/source/fitz/document.c:1019:4
    #25 0x5613298ec0fd in fz_run_page /home/hexijie/fuzz/project/mupdf/source/fitz/document.c:1069:2
    #26 0x561329a90100 in fz_new_pixmap_from_page_with_separations /home/hexijie/fuzz/project/mupdf/source/fitz/util.c:229:3
    #27 0x561329a906f6 in fz_new_pixmap_from_page_number_with_separations /home/hexijie/fuzz/project/mupdf/source/fitz/util.c:259:9
    #28 0x561329a90431 in fz_new_pixmap_from_page_number /home/hexijie/fuzz/project/mupdf/source/fitz/util.c:248:9
    #29 0x5613298d0dd3 in LLVMFuzzerTestOneInput /home/hexijie/fuzz/project/pdf_fuzzer.cc:146:13
    #30 0x5613297dbfe4 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/hexijie/fuzz/fuzzers/pdf_fuzzer+0x204fe4) (BuildId: 50fe013c4800d28f43269fb98442376d226dfa08)
    #31 0x5613297c5116 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/home/hexijie/fuzz/fuzzers/pdf_fuzzer+0x1ee116) (BuildId: 50fe013c4800d28f43269fb98442376d226dfa08)
    #32 0x5613297cabca in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/hexijie/fuzz/fuzzers/pdf_fuzzer+0x1f3bca) (BuildId: 50fe013c4800d28f43269fb98442376d226dfa08)
    #33 0x5613297f5386 in main (/home/hexijie/fuzz/fuzzers/pdf_fuzzer+0x21e386) (BuildId: 50fe013c4800d28f43269fb98442376d226dfa08)
    #34 0x7f35c7a2a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #35 0x7f35c7a2a28a in __libc_start_main csu/../csu/libc-start.c:360:3
    #36 0x5613297bfce4 in _start (/home/hexijie/fuzz/fuzzers/pdf_fuzzer+0x1e8ce4) (BuildId: 50fe013c4800d28f43269fb98442376d226dfa08)

0x504000000ac0 is located 8 bytes after 40-byte region [0x504000000a90,0x504000000ab8)
allocated by thread T0 here:
    #0 0x561329890113 in malloc (/home/hexijie/fuzz/fuzzers/pdf_fuzzer+0x2b9113) (BuildId: 50fe013c4800d28f43269fb98442376d226dfa08)
    #1 0x5613298d10f2 in fz_malloc_ossfuzz(void*, unsigned long) /home/hexijie/fuzz/project/pdf_fuzzer.cc:55:18
    #2 0x561329a0b347 in do_scavenging_malloc /home/hexijie/fuzz/project/mupdf/source/fitz/memory.c:52:7
    #3 0x561329a0b88d in fz_calloc_no_throw /home/hexijie/fuzz/project/mupdf/source/fitz/memory.c:165:6
    #4 0x5613299dd66d in fz_opj_calloc /home/hexijie/fuzz/project/mupdf/source/fitz/load-jpx.c:143:9
    #5 0x56132aa44cdf in fz_opj_j2k_build_tp_index_from_tlm /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:8939:57
    #6 0x56132aa40768 in fz_opj_j2k_read_header_procedure /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:9152:5
    #7 0x56132aa24328 in fz_opj_j2k_exec /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:9181:33
    #8 0x56132aa23ee1 in fz_opj_j2k_read_header /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:8526:11
    #9 0x56132a4c111f in fz_opj_read_header /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/openjpeg.c:475:16
    #10 0x5613299ddfd5 in jpx_read_image /home/hexijie/fuzz/project/mupdf/source/fitz/load-jpx.c:463:7
    #11 0x5613299dda60 in fz_load_jpx /home/hexijie/fuzz/project/mupdf/source/fitz/load-jpx.c:653:9
    #12 0x5613299a65e5 in compressed_image_get_pixmap /home/hexijie/fuzz/project/mupdf/source/fitz/image.c:843:10
    #13 0x5613299a1689 in fz_get_pixmap_from_image /home/hexijie/fuzz/project/mupdf/source/fitz/image.c:1102:9
    #14 0x56132990211c in fz_draw_fill_image /home/hexijie/fuzz/project/mupdf/source/fitz/draw-device.c:1903:11
    #15 0x561329bb6e29 in fz_fill_image /home/hexijie/fuzz/project/mupdf/source/fitz/device.c:384:4
    #16 0x561329e4ac67 in pdf_show_image_imp /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-op-run.c:879:3
    #17 0x561329e4a618 in pdf_show_image /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-op-run.c:943:4
    #18 0x561329e33f90 in pdf_run_Do_image /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-op-run.c:3229:2
    #19 0x561329db1fc2 in pdf_process_Do /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1081:5
    #20 0x561329dae1df in pdf_process_keyword /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1511:19
    #21 0x561329da48d9 in pdf_process_stream /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1686:6
    #22 0x561329da2bff in pdf_process_raw_contents /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1826:3
    #23 0x561329da50db in pdf_process_contents /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-interpret.c:1849:3
    #24 0x561329e73487 in pdf_run_page_contents_with_usage_imp /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-run.c:187:3
    #25 0x561329e7241c in pdf_run_page_contents_with_usage /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-run.c:224:3
    #26 0x561329e738e4 in pdf_run_page_contents /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-run.c:239:2
    #27 0x561329e5ff9d in pdf_run_page_contents_imp /home/hexijie/fuzz/project/mupdf/source/pdf/pdf-page.c:1124:2
    #28 0x5613298eb78a in fz_run_page_contents /home/hexijie/fuzz/project/mupdf/source/fitz/document.c:1019:4
    #29 0x5613298ec0fd in fz_run_page /home/hexijie/fuzz/project/mupdf/source/fitz/document.c:1069:2

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/hexijie/fuzz/project/mupdf/thirdparty/openjpeg/src/lib/openjp2/j2k.c:5086:13 in fz_opj_j2k_read_sod
Shadow bytes around the buggy address:
  0x504000000800: fa fa 00 00 00 00 00 00 fa fa 00 00 00 00 00 fa
  0x504000000880: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 00
  0x504000000900: fa fa 00 00 00 00 00 00 fa fa 00 00 00 00 00 fa
  0x504000000980: fa fa 00 00 00 00 00 00 fa fa 00 00 00 00 00 fa
  0x504000000a00: fa fa fd fd fd fd fd fa fa fa fd fd fd fd fd fa
=>0x504000000a80: fa fa 00 00 00 00 00 fa[fa]fa 00 00 00 00 00 fa
  0x504000000b00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x504000000b80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x504000000c00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x504000000c80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x504000000d00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==100451==ABORTING
```
