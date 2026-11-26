# Update 2026-11-26
## CVE-2026-136131
 hping3 through commit 3547c76 contains an out-of-bounds write vulnerability in display_ipopt() that allows remote attackers to overflow the static 40-byte old_rr buffer via a crafted IP Record Route option. Attackers acting as the probed host, on-path, or spoofing the target can send replies with option lengths up to 255 to hping3 running with -G/--rroute, corrupting global memory and crashing hping3.

- [https://github.com/VulnSVNC/CVE-2026-136131](https://github.com/VulnSVNC/CVE-2026-136131) :  ![starts](https://img.shields.io/github/stars/VulnSVNC/CVE-2026-136131.svg) ![forks](https://img.shields.io/github/forks/VulnSVNC/CVE-2026-136131.svg)


## CVE-2026-136126
 c-icap-server through 0.5.15 and 0.6.5 contains an out-of-bounds write in process_encapsulated() that allows unauthenticated attackers to corrupt heap memory by sending six Encapsulated entities. Attackers can send a single ICAP request whose sixth entity overwrites trash_entities[0], triggering use-after-free and double free in ci_request_destroy() during teardown.

- [https://github.com/cveForge/CVE-2026-136126](https://github.com/cveForge/CVE-2026-136126) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-136126.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-136126.svg)


## CVE-2026-136123
 Friendica through 2026.05-1 contains an improper validation vulnerability in APContact::compactProfile() that allows remote actors to overwrite a local user's stored inbox and public key by declaring that user's profile URL as their actor id. Attackers can then sign ActivityPub activities that HTTPSignature::fetchKey() verifies against the injected publicKeyPem, impersonating the local user on the instance.

- [https://github.com/cveForge/CVE-2026-136123](https://github.com/cveForge/CVE-2026-136123) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-136123.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-136123.svg)


## CVE-2026-136120
 Ziit 1.3.2 contains a cross-site request forgery vulnerability in the /api/auth/epilogue/callback handler that accepts requests lacking the OAuth state parameter. Attackers can lure a signed-in victim to a cross-site page that completes the link flow with the attacker's Epilogue authorization code, letting the attacker sign in as the victim.

- [https://github.com/cveForge/CVE-2026-136120](https://github.com/cveForge/CVE-2026-136120) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-136120.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-136120.svg)


## CVE-2026-135745
 FFmpeg before 9.1 contains a heap out-of-bounds read vulnerability in the curves filter in libavfilter/vf_curves.c that allows attackers to read past lookup tables by supplying planar high bit depth samples exceeding the nominal depth. Attackers can craft video files with unmasked gbrp9 to gbrp14 samples passed through the rawvideo decoder to crash applications or leak heap contents into output video.

- [https://github.com/googlesky/CVE-2026-135745](https://github.com/googlesky/CVE-2026-135745) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135745.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135745.svg)


## CVE-2026-135744
 FFmpeg before 9.1 contains an out-of-bounds read vulnerability in the lut1d filter in libavfilter/vf_lut3d.c that allows attackers to read heap memory by supplying planar high bit depth samples above the nominal depth. Attackers can craft 9, 10, 12 or 14 bit planar RGB video processed with a large 1D LUT to crash applications or disclose heap contents in output pixels.

- [https://github.com/googlesky/CVE-2026-135744](https://github.com/googlesky/CVE-2026-135744) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135744.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135744.svg)


## CVE-2026-135743
 FFmpeg 4.3 before 9.1 contains a heap out-of-bounds read and write vulnerability in the dynaudnorm filter because cqueue_resize() miscalculates gain history queue element counts when gausssize changes at runtime. Attackers can send gausssize commands via asendcmd scripts or an unauthenticated azmq filter to corrupt heap memory, crashing the process or potentially executing code.

- [https://github.com/cveForge/CVE-2026-135743](https://github.com/cveForge/CVE-2026-135743) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135743.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135743.svg)


## CVE-2026-135742
 FFmpeg before 9.1 contains a heap buffer overflow vulnerability in recv_msg() of the zmq and azmq filters that allows unauthenticated network attackers to corrupt memory by sending oversized command messages. Attackers can send a 4 GiB message to the default listening port, truncating the int buffer size so memcpy() writes past the heap allocation and crashes FFmpeg.

- [https://github.com/googlesky/CVE-2026-135742](https://github.com/googlesky/CVE-2026-135742) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135742.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135742.svg)
- [https://github.com/cveForge/CVE-2026-135742](https://github.com/cveForge/CVE-2026-135742) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135742.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135742.svg)


## CVE-2026-135741
 FFmpeg before 9.1 contains a heap out-of-bounds read vulnerability in libavfilter/vf_lut2.c because the second input's pixel format is unrestricted when the output depth option is set. Attackers can supply crafted media such as monoblack BMP or PBM images to index beyond lookup tables, crashing applications or leaking heap contents into output video.

- [https://github.com/googlesky/CVE-2026-135741](https://github.com/googlesky/CVE-2026-135741) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135741.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135741.svg)


## CVE-2026-135740
 FFmpeg before 9.1 contains a heap out-of-bounds write vulnerability in libavfilter/vf_readeia608.c because build_histogram() does not clamp high bit depth luma samples to the nominal maximum. Attackers can supply crafted 9, 10, 12 or 14 bit gray or YUV video to corrupt heap memory, causing crashes or possibly code execution.

- [https://github.com/googlesky/CVE-2026-135740](https://github.com/googlesky/CVE-2026-135740) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135740.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135740.svg)
- [https://github.com/cveForge/CVE-2026-135740](https://github.com/cveForge/CVE-2026-135740) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135740.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135740.svg)


## CVE-2026-135739
 FFmpeg 7.1 before 9.1 contains an out-of-bounds read vulnerability in libavfilter/vf_scale.c that allows attackers to read past the filter input array by sending width or height commands using ref variables. Attackers can send such commands via sendcmd scripts or unauthenticated zmq or azmq filters, causing config_props() to dereference an invalid pointer and crash the process.

- [https://github.com/googlesky/CVE-2026-135739](https://github.com/googlesky/CVE-2026-135739) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135739.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135739.svg)


## CVE-2026-135738
 FFmpeg before 9.1 contains a heap out-of-bounds write vulnerability in libavfilter/vf_signalstats.c that allows attackers to corrupt heap memory by supplying high bit depth samples exceeding the nominal maximum. Attackers can craft planar 9 to 14 bit YUV video whose unclamped samples or saturation values index past histogram ends, crashing applications or possibly executing code.

- [https://github.com/googlesky/CVE-2026-135738](https://github.com/googlesky/CVE-2026-135738) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135738.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135738.svg)
- [https://github.com/cveForge/CVE-2026-135738](https://github.com/cveForge/CVE-2026-135738) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135738.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135738.svg)


## CVE-2026-135737
 FFmpeg before 9.1 contains a heap out-of-bounds write and read vulnerability in the tmidequalizer filter that allows attackers to corrupt memory by supplying high bit depth samples exceeding the nominal maximum. Attackers can craft planar 9, 10, 12 or 14 bit video so compute_histogram16() and apply_contrast_change16() index unclamped samples, crashing applications, corrupting the heap, and leaking heap contents.

- [https://github.com/cveForge/CVE-2026-135737](https://github.com/cveForge/CVE-2026-135737) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135737.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135737.svg)
- [https://github.com/googlesky/CVE-2026-135737](https://github.com/googlesky/CVE-2026-135737) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135737.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135737.svg)


## CVE-2026-135736
 FFmpeg 4.4 before 9.1 contains a heap out-of-bounds read and write vulnerability in libavfilter/vf_deband.c that allows attackers to corrupt heap memory by sending a runtime coupling command. Attackers can send a 'deband coupling 1' command via sendcmd or an unauthenticated zmq filter, making chroma planes be processed at luma dimensions to crash the process or potentially execute code.

- [https://github.com/googlesky/CVE-2026-135736](https://github.com/googlesky/CVE-2026-135736) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135736.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135736.svg)


## CVE-2026-135735
 FFmpeg before 9.1 contains a heap out-of-bounds read vulnerability in filter_slice_rgba_planar() that allows attackers to read beyond lookup tables using unmasked high bit depth planar samples. Attackers can supply crafted video with samples exceeding the nominal depth, passed unchanged by rawvideo, to crash the application or leak heap contents into output video.

- [https://github.com/googlesky/CVE-2026-135735](https://github.com/googlesky/CVE-2026-135735) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135735.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135735.svg)


## CVE-2026-135734
 FFmpeg before 9.1 contains a heap out-of-bounds write vulnerability in the deflicker filter that lets attackers corrupt heap memory via unclamped high bit depth luma samples. Attackers can supply crafted video whose luma values exceed the nominal depth, making calc_avgy16() increment counters past the histogram allocation, causing crashes or possibly code execution.

- [https://github.com/googlesky/CVE-2026-135734](https://github.com/googlesky/CVE-2026-135734) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135734.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135734.svg)
- [https://github.com/cveForge/CVE-2026-135734](https://github.com/cveForge/CVE-2026-135734) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135734.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135734.svg)


## CVE-2026-135733
 FFmpeg through 9.1 contains an insecure default configuration in the zmq and azmq filters of libavfilter/f_zmq.c that binds an unauthenticated command socket to all interfaces on TCP port 5555. Remote attackers can send 'TARGET COMMAND [ARG]' messages passed to avfilter_graph_send_command() to change filter runtime parameters and alter processed audio or video.

- [https://github.com/googlesky/CVE-2026-135733](https://github.com/googlesky/CVE-2026-135733) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135733.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135733.svg)


## CVE-2026-135732
 FFmpeg before 9.1 contains an out-of-bounds read vulnerability in mxf_write_d10_audio_packet() in libavformat/mxfenc.c because mxf_init() accepts unsupported D-10 audio codecs. Attackers can supply a crafted input with a non-PCM multichannel audio stream remuxed to D-10 MXF to leak heap memory into the output file or crash the application.

- [https://github.com/googlesky/CVE-2026-135732](https://github.com/googlesky/CVE-2026-135732) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135732.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135732.svg)


## CVE-2026-135731
 FFmpeg before 9.1 contains an integer overflow in send_picture() of libavformat/rtpenc_vc2hq.c that leaves the bit reader without a buffer, causing a NULL pointer dereference. Attackers can supply a Dirac/VC-2 stream with a picture data unit of about 256 MiB or more to crash applications packetizing it to RTP.

- [https://github.com/googlesky/CVE-2026-135731](https://github.com/googlesky/CVE-2026-135731) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135731.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135731.svg)


## CVE-2026-135730
 FFmpeg before 9.1 contains an uninitialized memory vulnerability in vpk_read_header() in libavformat/vpk.c that computes a last block size not divisible by the channel count. Attackers can supply a crafted VPK file with a large channel count so the last audio packet exposes leftover heap memory contents.

- [https://github.com/googlesky/CVE-2026-135730](https://github.com/googlesky/CVE-2026-135730) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135730.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135730.svg)


## CVE-2026-135729
 FFmpeg before 9.1 contains an XML injection vulnerability in write_adaptation_set() in libavformat/webmdashenc.c that writes stream language metadata unescaped into the AdaptationSet lang attribute. Attackers can supply crafted WebM files whose track language contains quotes or angle brackets to inject attributes or elements, controlling segment URLs and representations in generated MPD manifests.

- [https://github.com/googlesky/CVE-2026-135729](https://github.com/googlesky/CVE-2026-135729) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135729.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135729.svg)


## CVE-2026-135728
 FFmpeg before 9.1 contains a signed integer overflow vulnerability in libavformat/dashdec.c that allows attackers to crash applications by supplying a crafted DASH manifest. Attackers can craft an MPD manifest with very long BaseURL and SegmentTemplate strings to overflow max_url_size, causing undersized URL allocations and denial of service.

- [https://github.com/googlesky/CVE-2026-135728](https://github.com/googlesky/CVE-2026-135728) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135728.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135728.svg)


## CVE-2026-135726
 FFmpeg before 9.1 contains a NULL pointer dereference vulnerability in rdt_parse_packet() in libavformat/rdt.c that allows remote attackers to crash applications by omitting the ASMRuleBook SDP attribute. Attackers can serve an RTSP session selecting RDT transport without ASMRuleBook, then send an RDT data packet to crash ffmpeg or ffprobe.

- [https://github.com/googlesky/CVE-2026-135726](https://github.com/googlesky/CVE-2026-135726) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135726.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135726.svg)


## CVE-2026-135725
 FFmpeg before 9.1 contains a stack-based buffer overflow vulnerability in ff_rtmp_packet_write() in libavformat/rtmppkt.c that allows malicious RTMP servers to overflow a 16-byte header buffer. Attackers can send a Set Chunk Size packet on a high channel id with an extended timestamp, which handle_chunk_size() echoes back, corrupting the publishing client's stack.

- [https://github.com/googlesky/CVE-2026-135725](https://github.com/googlesky/CVE-2026-135725) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135725.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135725.svg)
- [https://github.com/cveForge/CVE-2026-135725](https://github.com/cveForge/CVE-2026-135725) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135725.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135725.svg)


## CVE-2026-135724
 FFmpeg before 9.1 contains a NULL pointer dereference vulnerability in avformat_stream_group_create() in libavformat/options.c that sets the group type before allocating parameters. Attackers can supply crafted HEIF/AVIF files whose tile grid parsing under allocation failure makes ff_free_stream_group() dereference a NULL tile_grid, crashing the application.

- [https://github.com/googlesky/CVE-2026-135724](https://github.com/googlesky/CVE-2026-135724) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135724.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135724.svg)


## CVE-2026-135723
 FFmpeg before 9.1 contains a double free vulnerability in the fill_marker() function of libavformat/imf_cpl.c that frees a Marker label without clearing the pointer when default scope allocation fails. Attackers can supply a crafted Composition Playlist with a Marker Label lacking a scope attribute, triggering a second free in imf_marker_free() under memory pressure and causing memory corruption or a crash.

- [https://github.com/googlesky/CVE-2026-135723](https://github.com/googlesky/CVE-2026-135723) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135723.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135723.svg)


## CVE-2026-135722
 FFmpeg before 9.1 contains a heap-based buffer overflow vulnerability in peak_init_writer() and wav_write_packet() in libavformat/wavenc.c that allows attackers to corrupt heap memory by supplying audio with zero channels. Attackers can provide a crafted PCM stream declaring no channels for WAV output with peak envelope enabled, causing out-of-bounds writes past peak_maxpos and peak_maxneg arrays, crashes, and potential code execution.

- [https://github.com/cveForge/CVE-2026-135722](https://github.com/cveForge/CVE-2026-135722) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135722.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135722.svg)
- [https://github.com/googlesky/CVE-2026-135722](https://github.com/googlesky/CVE-2026-135722) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135722.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135722.svg)


## CVE-2026-135721
 FFmpeg before 9.1 contains an infinite loop vulnerability in ff_rtp_send_vc2hq() in libavformat/rtpenc_vc2hq.c that accepts a Dirac next parse offset of zero. Attackers can supply crafted Dirac/VC-2 video remuxed to the RTP muxer, causing the parsing pointer to never advance and consume CPU indefinitely.

- [https://github.com/googlesky/CVE-2026-135721](https://github.com/googlesky/CVE-2026-135721) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135721.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135721.svg)


## CVE-2026-135720
 FFmpeg 9.0 before 9.1 contains a NULL pointer dereference vulnerability in dash_read_header() in libavformat/dashdec.c when building LCEVC stream groups without checking for a missing codecs string. Attackers can supply a crafted MPD manifest with a representation declaring a dependencyId but no codecs attribute to crash applications using the DASH demuxer.

- [https://github.com/googlesky/CVE-2026-135720](https://github.com/googlesky/CVE-2026-135720) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135720.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135720.svg)


## CVE-2026-135719
 FFmpeg before 9.1 contains an uninitialized memory disclosure vulnerability in dxa_read_packet() in libavformat/dxa.c that ignores short avio_read() results for CMAP palette data. Attackers can supply a crafted DXA stream over a stalling network source so uninitialized stack bytes are copied into returned video packets and decoded frames.

- [https://github.com/googlesky/CVE-2026-135719](https://github.com/googlesky/CVE-2026-135719) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135719.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135719.svg)


## CVE-2026-135718
 FFmpeg 7.0 before 9.1 contains an out-of-bounds read vulnerability in dvdvideo_audio_stream_add_all() in libavformat/dvdvideodec.c when parsing menu audio streams. Attackers can supply a crafted DVD image whose menu IFO declares more than 8 audio streams, reading past the audio_control array and crashing applications.

- [https://github.com/googlesky/CVE-2026-135718](https://github.com/googlesky/CVE-2026-135718) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135718.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135718.svg)


## CVE-2026-135717
 FFmpeg 8.0 before 9.1 contains a use of uninitialized memory vulnerability in opus_parse_packet() in libavformat/rtpdec_opus.c that reads the Opus TOC byte from stale buffer memory when parsing empty RTP payloads. A malicious RTSP server or RTP sender can deliver an empty Opus payload to cause incorrect packet durations and leak bits of stale memory through pkt-duration.

- [https://github.com/googlesky/CVE-2026-135717](https://github.com/googlesky/CVE-2026-135717) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135717.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135717.svg)


## CVE-2026-135716
 FFmpeg before 9.1 contains an out-of-bounds write vulnerability in build_frame_code() in libavformat/nutenc.c that allows attackers to corrupt the header_len[] array by supplying inputs with many audio streams. Attackers can remux a crafted input with many audio streams to NUT, causing out-of-bounds reads past static header tables and crashing the application.

- [https://github.com/googlesky/CVE-2026-135716](https://github.com/googlesky/CVE-2026-135716) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135716.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135716.svg)


## CVE-2026-135715
 FFmpeg before 9.1 contains a NULL pointer dereference vulnerability in the AVIF muxer in libavformat/movenc.c that allows attackers to crash the application through streams with unknown pixel formats. Attackers can supply a crafted input whose video stream is stream-copied to AVIF, causing unchecked av_pix_fmt_desc_get() results to be dereferenced, resulting in denial of service.

- [https://github.com/googlesky/CVE-2026-135715](https://github.com/googlesky/CVE-2026-135715) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135715.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135715.svg)


## CVE-2026-135714
 FFmpeg before 9.1 contains an information disclosure vulnerability in amf_get_field_value2() in libavformat/rtmppkt.c that NUL-terminates truncated AMF strings at the declared length instead of bytes read. A malicious RTMP server, or connecting client in listen mode, can send truncated onStatus or _error strings to leak uninitialized stack memory through log messages.

- [https://github.com/googlesky/CVE-2026-135714](https://github.com/googlesky/CVE-2026-135714) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135714.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135714.svg)


## CVE-2026-135713
 FFmpeg before 9.1 contains a NULL pointer dereference vulnerability in libavformat/mmst.c that allows malicious MMS servers to crash clients by sending malformed ASF headers. Attackers can send an ASF header lacking a packet size or stream properties, causing mms_open() to return success after freeing state and crash on first read.

- [https://github.com/googlesky/CVE-2026-135713](https://github.com/googlesky/CVE-2026-135713) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135713.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135713.svg)


## CVE-2026-135712
 FFmpeg before 9.1 contains an integer overflow vulnerability in the split_planes size check of write_packet() in libavformat/img2enc.c that allows out-of-bounds heap reads. Attackers can supply a crafted input whose rawvideo stream declares very large width and height, remuxed into .y image files, to leak heap memory into output files or crash the application.

- [https://github.com/googlesky/CVE-2026-135712](https://github.com/googlesky/CVE-2026-135712) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135712.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135712.svg)


## CVE-2026-135711
 FFmpeg before 9.1 contains an XML injection vulnerability in ttml_write_header() in libavformat/ttmlenc.c that writes stream language metadata unescaped into the xml:lang attribute. Attackers can supply media files, such as Matroska subtitle tracks with crafted Language values, to inject markup into converted TTML documents and alter downstream parsing or rendering.

- [https://github.com/googlesky/CVE-2026-135711](https://github.com/googlesky/CVE-2026-135711) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135711.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135711.svg)


## CVE-2026-135710
 FFmpeg before 9.1 contains an uninitialized memory disclosure vulnerability in vmd_read_packet() in libavformat/sierravmd.c that leaves 16 packet bytes unwritten for Indeo3 frames. Attackers can supply a crafted VMD file with Indeo3 video to expose leftover heap contents in demuxed packets, such as stream-copied output files.

- [https://github.com/googlesky/CVE-2026-135710](https://github.com/googlesky/CVE-2026-135710) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135710.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135710.svg)


## CVE-2026-135709
 FFmpeg before 9.1 contains an out-of-bounds write vulnerability in ogg_buffer_data() in libavformat/oggenc.c because ogg_buffer_page() leaves a full page current after failed allocation. When page allocation fails, a memset with length (size_t)-1 or an overflowing memcpy writes past the segment table, causing heap memory corruption and crashes when writing Ogg output.

- [https://github.com/googlesky/CVE-2026-135709](https://github.com/googlesky/CVE-2026-135709) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135709.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135709.svg)


## CVE-2026-135708
 FFmpeg 8.0 before 9.1 contains an improper URL scheme validation vulnerability in the WHIP muxer that allows malicious WHIP servers to create or truncate local files via the Location header. Attackers can return a file: URL that dispose_session() opens read-write with truncation on teardown, destroying arbitrary user-writable files or redirecting requests to other protocols.

- [https://github.com/googlesky/CVE-2026-135708](https://github.com/googlesky/CVE-2026-135708) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135708.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135708.svg)


## CVE-2026-135707
 FFmpeg before 9.1 contains an uninitialized memory vulnerability in nist_read_header() in libavformat/nistspheredec.c, where an inverted ff_alloc_extradata() return check leaves the embedded-shorten extradata byte uninitialized. Attackers can supply a crafted NIST SPHERE file declaring pcm,embedded-shorten coding to leak an uninitialized heap byte into copied output or trigger a NULL pointer write on allocation failure.

- [https://github.com/googlesky/CVE-2026-135707](https://github.com/googlesky/CVE-2026-135707) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135707.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135707.svg)


## CVE-2026-135706
 FFmpeg before 9.1 contains a heap buffer overflow vulnerability in modplug_read_header() in libavformat/libmodplug.c that allocates the buffer using max_size instead of sz. When max_size is set to 0, attackers can supply crafted module files that avio_read() copies into a zero-sized buffer, causing memory corruption, crashes, or possible code execution.

- [https://github.com/googlesky/CVE-2026-135706](https://github.com/googlesky/CVE-2026-135706) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135706.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135706.svg)
- [https://github.com/cveForge/CVE-2026-135706](https://github.com/cveForge/CVE-2026-135706) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135706.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135706.svg)


## CVE-2026-135705
 FFmpeg before 9.1 contains a stack out-of-bounds read vulnerability in ff_h264_parse_framesize() in libavformat/rtpdec_h264.c when parsing an SDP a=framesize attribute lacking a height. Attackers controlling an RTSP server DESCRIBE response or a crafted .sdp file can make atoi() read past the line buffer, crashing clients or parsing stale stack bytes.

- [https://github.com/googlesky/CVE-2026-135705](https://github.com/googlesky/CVE-2026-135705) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135705.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135705.svg)


## CVE-2026-135704
 FFmpeg before 9.1 contains an information disclosure vulnerability in the MXG demuxer's mxg_read_packet() that allows attackers to leak uninitialized heap memory through truncated marker segments. Attackers can supply a crafted MXG file ending in a truncated APP13 segment with a large declared length, causing uninitialized heap contents to be emitted as audio packet payload, for example into remuxed output files.

- [https://github.com/googlesky/CVE-2026-135704](https://github.com/googlesky/CVE-2026-135704) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135704.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135704.svg)


## CVE-2026-135703
 FFmpeg before 9.1 contains an uninitialized memory use vulnerability in asfrtp_parse_packet() in libavformat/rtpdec_asf.c that allows malicious RTP sources to leak heap contents by supplying an oversized ASF packet length. Attackers controlling an RTSP server with an x-asf-pf payload can set len_off beyond the RTP payload so the ASF demuxer returns stale heap memory as demuxed media data.

- [https://github.com/googlesky/CVE-2026-135703](https://github.com/googlesky/CVE-2026-135703) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135703.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135703.svg)


## CVE-2026-135695
 rConfig Core 8.0.0 before 8.2.13 and rConfig Pro before 8.4.0 contain an authorization bypass vulnerability in the users API that allows authenticated users to modify other accounts. Attackers can send a UserController::update request with an administrator's user id and new password, then log in as that administrator to take full control.

- [https://github.com/cveForge/CVE-2026-135695](https://github.com/cveForge/CVE-2026-135695) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135695.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135695.svg)


## CVE-2026-135693
 rConfig Core 8.0.0 before 8.2.17 and rConfig Pro before 8.4.0 contain a stored cross-site scripting vulnerability in the Config Search View Matches dialog, which renders configuration context via v-html without escaping. Attackers can place markup in device banners, interface descriptions, ACL remarks or SNMP locations to execute script in a user's session and read stored configurations containing secrets.

- [https://github.com/cveForge/CVE-2026-135693](https://github.com/cveForge/CVE-2026-135693) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135693.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135693.svg)


## CVE-2026-135691
 Open5GS WebUI through 2.8.0 contains an incorrect authorization vulnerability in webui/server/routes/db.js that allows authenticated user-role accounts to modify the Account model. Attackers can send PATCH /api/db/Account/username setting roles to admin, overwrite password hashes, delete accounts, and read hashes to gain full administrative control.

- [https://github.com/cveForge/CVE-2026-135691](https://github.com/cveForge/CVE-2026-135691) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135691.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135691.svg)


## CVE-2026-135689
 Community Store for Concrete CMS before 2.8.0 contains a stored cross-site scripting vulnerability that allows unauthenticated attackers to inject script via the order email in single_pages/dashboard/store/orders.php. Attackers can place guest orders with quoted email local parts containing markup to execute script in a store manager's session when viewing the order.

- [https://github.com/cveForge/CVE-2026-135689](https://github.com/cveForge/CVE-2026-135689) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135689.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135689.svg)


## CVE-2026-135686
 Trilium through 0.107.0 contains an sql injection vulnerability in updateNormalEntity() that allows malicious sync partners to inject SQL by supplying crafted entity names and column keys. Attackers can abuse /api/sync/changed or PUT /api/sync/update data to copy sessions, etapi_tokens and user_data into synced rows and write arbitrary database rows.

- [https://github.com/cveForge/CVE-2026-135686](https://github.com/cveForge/CVE-2026-135686) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135686.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135686.svg)


## CVE-2026-135617
 Lookyloo is a web-based URL capture and analysis platform. Prior to the fix, the authorization mechanism for private captures (seed-based access control) was not consistently enforced at the data access layer. The capture_cache method and numerous internal methods (get_info, get_meta, get_statistics, get_modules_responses, get_data, get_video, get_screenshot, get_har, get_cookies, get_storage_state, get_frames, get_console_messages, get_capture, get_ressource, misp_export, lacus_export, ai_export, comparator functions, and others) could be invoked with only a capture UUID without validating the required seed token. This meant that API endpoints and internal code paths that called these methods directly could return private capture data to unauthenticated users or users lacking the correct seed. The before_request hook in the web interface provided a partial check, but the underlying data layer did not enforce it, creating an inconsistent authorization boundary. An attacker who knew or guessed a private capture UUID could potentially access sensitive data including rendered screenshots, HAR files, downloaded files, cookies, storage state, console messages, and MISP exports through various REST API endpoints and web routes. The fix introduces a LookylooPrivateCapture exception raised at the cache layer when a private capture is accessed without a valid seed, refactors the API to pass CaptureCache objects (already validated) rather than raw UUIDs, and ensures all web and API endpoints propagate the session-known seed or admin status to the data access layer. Background processes use an explicit unsafe=True flag to bypass the check, as they operate server-side with full trust.

- [https://github.com/googlesky/CVE-2026-135617](https://github.com/googlesky/CVE-2026-135617) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135617.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135617.svg)


## CVE-2026-135436
 KindleEar 3.0.0 through 3.5.3 contains a remote code execution vulnerability that allows authenticated non-admin users to run Python code by uploading malicious recipes. Attackers can submit crafted recipe source to the /recipe/upload action, which calibre compile_recipe executes via exec() without sandboxing, gaining root code execution in the Docker container and access to password hashes.

- [https://github.com/cveForge/CVE-2026-135436](https://github.com/cveForge/CVE-2026-135436) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135436.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135436.svg)


## CVE-2026-135300
 Pomerium from 0.30.0 before 0.34.0 contains an authentication bypass vulnerability in the MCP token endpoint that skips client secret verification for client_secret_basic clients. Attackers holding an intercepted authorization code or refresh token can redeem it at /.pomerium/mcp/token with any secret to obtain the victim's access tokens.

- [https://github.com/cveForge/CVE-2026-135300](https://github.com/cveForge/CVE-2026-135300) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135300.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135300.svg)


## CVE-2026-135298
 Convoy before 26.6.0 contains an insecure direct object reference vulnerability in /portal-api single-resource handlers that allows portal link token holders to access other tenants' resources by ID. Attackers with another tenant's resource IDs in the same project can read endpoint signing secrets and webhook payloads, rotate secrets, pause or delete endpoints, and force event re-delivery.

- [https://github.com/cveForge/CVE-2026-135298](https://github.com/cveForge/CVE-2026-135298) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135298.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135298.svg)


## CVE-2026-135260
Affected: MISP versions prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135260](https://github.com/googlesky/CVE-2026-135260) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135260.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135260.svg)


## CVE-2026-135259
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135259](https://github.com/googlesky/CVE-2026-135259) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135259.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135259.svg)


## CVE-2026-135257
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135257](https://github.com/googlesky/CVE-2026-135257) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135257.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135257.svg)


## CVE-2026-135256
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135256](https://github.com/googlesky/CVE-2026-135256) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135256.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135256.svg)


## CVE-2026-135253
Affected: MISP versions prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135253](https://github.com/googlesky/CVE-2026-135253) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135253.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135253.svg)


## CVE-2026-135252
Affected: MISP versions prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135252](https://github.com/googlesky/CVE-2026-135252) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135252.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135252.svg)


## CVE-2026-135250
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135250](https://github.com/googlesky/CVE-2026-135250) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135250.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135250.svg)


## CVE-2026-135249
Affected: MISP versions prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135249](https://github.com/googlesky/CVE-2026-135249) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135249.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135249.svg)


## CVE-2026-135248
Affected: MISP versions prior to 2.5.52

- [https://github.com/googlesky/CVE-2026-135248](https://github.com/googlesky/CVE-2026-135248) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135248.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135248.svg)


## CVE-2026-135247
Affected versions: MISP prior to 2.5.52

- [https://github.com/googlesky/CVE-2026-135247](https://github.com/googlesky/CVE-2026-135247) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135247.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135247.svg)


## CVE-2026-135245
Affected versions: MISP prior to 2.5.52

- [https://github.com/googlesky/CVE-2026-135245](https://github.com/googlesky/CVE-2026-135245) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135245.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135245.svg)


## CVE-2026-135244
Affected: MISP versions prior to 2.5.52

- [https://github.com/googlesky/CVE-2026-135244](https://github.com/googlesky/CVE-2026-135244) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135244.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135244.svg)


## CVE-2026-135243
The issue was reported by ENISA and fixed in version 2.5.52.

- [https://github.com/googlesky/CVE-2026-135243](https://github.com/googlesky/CVE-2026-135243) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135243.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135243.svg)


## CVE-2026-135242
Affected versions: MISP prior to 2.5.52

- [https://github.com/googlesky/CVE-2026-135242](https://github.com/googlesky/CVE-2026-135242) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135242.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135242.svg)


## CVE-2026-135241
The vulnerability affects MISP versions prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135241](https://github.com/googlesky/CVE-2026-135241) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135241.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135241.svg)


## CVE-2026-135239
Affected: MISP versions prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135239](https://github.com/googlesky/CVE-2026-135239) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135239.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135239.svg)


## CVE-2026-135237
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135237](https://github.com/googlesky/CVE-2026-135237) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135237.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135237.svg)


## CVE-2026-135236
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135236](https://github.com/googlesky/CVE-2026-135236) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135236.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135236.svg)


## CVE-2026-135235
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135235](https://github.com/googlesky/CVE-2026-135235) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135235.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135235.svg)


## CVE-2026-135233
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135233](https://github.com/googlesky/CVE-2026-135233) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135233.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135233.svg)


## CVE-2026-135232
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135232](https://github.com/googlesky/CVE-2026-135232) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135232.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135232.svg)


## CVE-2026-135231
Affected versions: MISP prior to 2.5.52.

- [https://github.com/googlesky/CVE-2026-135231](https://github.com/googlesky/CVE-2026-135231) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135231.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135231.svg)


## CVE-2026-135211
 BISHENG before 3.0.0 contains a missing authentication vulnerability in the /api/v2/workflow/invoke and /api/v2/workflow/stop routes that allows unauthenticated attackers to run workflows as the administrator. Attackers knowing a workflow UUID can supply an override replacing a Code node's code parameter with Python passed to exec(), achieving remote code execution, or stop other users' workflow sessions.

- [https://github.com/cveForge/CVE-2026-135211](https://github.com/cveForge/CVE-2026-135211) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135211.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135211.svg)


## CVE-2026-135210
 Plane before 1.5.0 contains a missing authorization vulnerability in WorkspaceDraftIssueViewSet that allows authenticated workspace members to create drafts in unauthorized projects by supplying an arbitrary project_id. Attackers can convert drafts into work items in private or removed-from projects with chosen title, state, assignees, cycle_id and module_ids, triggering notifications and disclosing project membership.

- [https://github.com/googlesky/CVE-2026-135210](https://github.com/googlesky/CVE-2026-135210) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135210.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135210.svg)


## CVE-2026-135208
 Kerberos Agent before 3.14.4 contains an authentication bypass vulnerability that allows unauthenticated attackers to forge administrator tokens because JWTMiddleWare() falls back to the hard-coded key TOBECHANGED. Attackers can sign HS256 tokens with arbitrary username and role claims to access /api and /config routes, exposing RTSP, ONVIF, Hub and encryption keys, rewriting configuration, and stopping the camera.

- [https://github.com/cveForge/CVE-2026-135208](https://github.com/cveForge/CVE-2026-135208) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135208.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135208.svg)


## CVE-2026-135207
 Healthchecks before 4.4 contains a verification bypass vulnerability that allows project users to mark arbitrary email addresses as verified because Channel.make_token() omits the email address. Attackers can verify an address they control, change the integration to a victim address, then reuse the original link to send unsolicited alert emails.

- [https://github.com/googlesky/CVE-2026-135207](https://github.com/googlesky/CVE-2026-135207) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135207.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135207.svg)


## CVE-2026-135202
 Several plugins for WordPress published by WP connect (Orders Sync to Airtable for WooCommerce, Add-On for Contact Form 7 to Notion, WP Sync for Notion – Notion to WordPress, Add-On for Contact Form 7 to Airtable, Add-on Brevo for Gravity Forms, and Air WP Sync – Airtable to WordPress) contain embedded malicious code (a backdoor) in the versions listed. The affected releases unconditionally load a backdoor module (includes/airwp-online.php) that runs on every request via the 'init' hook and on a half-hourly WP-Cron event, sends site information (site URL, PHP, WordPress and OS versions, and the server user) to a remote command-and-control server at tascredit-pay.com with TLS certificate verification disabled, and executes the PHP code returned by that server via eval(). The module also accepts queued commands that run shell commands, read, write and delete arbitrary files, query arbitrary database tables, dump the users table including password hashes, drop a webshell into the uploads directory, and install persistent hourly code execution. This makes it possible for unauthenticated attackers in control of the remote server, or able to intercept its traffic, to execute arbitrary code on the server and fully compromise affected sites. All affected plugins have been closed on WordPress.org and no patched versions are available; we strongly recommend uninstalling them and running a complete malware scan.

- [https://github.com/cveForge/CVE-2026-135202](https://github.com/cveForge/CVE-2026-135202) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135202.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135202.svg)


## CVE-2026-135175
 ZITADEL 4.19.5 before 4.20.3 contains a host header injection vulnerability that allows unauthenticated attackers to redirect notification links by placing a trusted host in the userinfo portion of the x-zitadel-public-host header. Attackers knowing a victim's login name can harvest single-use codes from password-reset links sent to their host, reset passwords, and take over accounts including administrators.

- [https://github.com/googlesky/CVE-2026-135175](https://github.com/googlesky/CVE-2026-135175) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135175.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135175.svg)
- [https://github.com/cveForge/CVE-2026-135175](https://github.com/cveForge/CVE-2026-135175) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135175.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135175.svg)


## CVE-2026-135173
 PdfPig through 0.1.16 contains an uncontrolled recursion vulnerability that allows attackers to crash applications by supplying crafted PDF documents with self-referencing AcroForm /Kids or deeply nested marked content. Attackers can trigger an uncatchable StackOverflowException in AcroFormFactory.GetAcroField or Page.GetOptionalContentsRecursively, terminating any process reading form fields or optional content.

- [https://github.com/googlesky/CVE-2026-135173](https://github.com/googlesky/CVE-2026-135173) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135173.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135173.svg)


## CVE-2026-135171
 Wing FTP Server before 8.2.8 contains a predictable session identifier vulnerability that allows unauthenticated attackers to hijack administrator sessions by deriving identifiers from process, time, ServerID, and client IP state. Attackers can enumerate candidate identifiers using the service_get_license.html endpoint as a validity oracle and replay live sessions to gain administrative control including the Lua console.

- [https://github.com/cveForge/CVE-2026-135171](https://github.com/cveForge/CVE-2026-135171) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135171.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135171.svg)


## CVE-2026-135167
 LibRaw 0.22.0 through 0.22.3 contains a heap out-of-bounds read vulnerability in HuffTable::len() because parse_dht() stores Huffman DC symbols without validating them as difference categories. Attackers can supply a crafted TIFF/ARW file with oversized Huffman symbols in a Sony YCbCr lossless JPEG stream to crash applications decoding it, causing denial of service.

- [https://github.com/googlesky/CVE-2026-135167](https://github.com/googlesky/CVE-2026-135167) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135167.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135167.svg)


## CVE-2026-135166
 Umbraco CMS 17.4.0 before 17.8.2 and 18.0.0 before 18.3.2 contains an information disclosure vulnerability because MemberValueSetBuilder.GetValueSets writes sensitive member properties into the Examine members index. Backoffice users with Settings and Members access but outside the Sensitive data group can search the index via the Examine Management dashboard or Management API to read hidden sensitive member values.

- [https://github.com/googlesky/CVE-2026-135166](https://github.com/googlesky/CVE-2026-135166) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135166.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135166.svg)


## CVE-2026-135160
 Medplum server 5.1.4 before 5.1.42 contains an incorrect authorization vulnerability in the Binary $presigned-url operation that allows non-admin project members to overwrite other projects' Binary content. Attackers in a project linked to another project can request a signed upload URL with upload=true for a readable Binary and overwrite its stored content, since project ownership is never verified.

- [https://github.com/googlesky/CVE-2026-135160](https://github.com/googlesky/CVE-2026-135160) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135160.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135160.svg)


## CVE-2026-135157
 Future AGI before 1.51.0 contains an authentication bypass vulnerability in ACSView.post that allows authenticated members of any organization to take over accounts in other organizations by asserting arbitrary e-mail addresses. Attackers can register a controlled identity provider through IDPUploadViews to obtain sessions as cross-tenant users, and can modify or delete other organizations' identity-provider configurations.

- [https://github.com/cveForge/CVE-2026-135157](https://github.com/cveForge/CVE-2026-135157) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-135157.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-135157.svg)


## CVE-2026-135155
 PodFetch 5.2.0 before 5.3.1 contains a missing authorization vulnerability in the Audiobookshelf-compatible POST /api/podcasts endpoint that allows authenticated low-privilege users to add podcasts by bypassing role and USER_PODCAST_LIMIT checks. Attackers with the plain user role can submit attacker-chosen feed URLs in media.metadata.feedUrl to force server-side fetching and episode downloads, consuming disk and bandwidth.

- [https://github.com/googlesky/CVE-2026-135155](https://github.com/googlesky/CVE-2026-135155) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135155.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135155.svg)


## CVE-2026-135154
 Tolgee before 3.242.5 fails to enforce email verification on the TOTP enable and recovery-code regeneration endpoints, allowing attackers to enroll MFA on unverified accounts via the @BypassEmailVerification annotation. Attackers can register with a victim's email, enroll an attacker-controlled TOTP factor through PUT /v2/user/mfa/totp, and permanently lock the legitimate owner out after verification and password reset.

- [https://github.com/googlesky/CVE-2026-135154](https://github.com/googlesky/CVE-2026-135154) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-135154.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-135154.svg)


## CVE-2026-134891
 A weakness has been identified in osCommerce 4.14.63493. This affects the function actionGiftCard of the file lib/frontend/controllers/CatalogController.php of the component Virtual Gift Card Basket. Executing a manipulation of the argument products_id can lead to authorization bypass. The attack can be executed remotely. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/cveForge/CVE-2026-134891](https://github.com/cveForge/CVE-2026-134891) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134891.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134891.svg)


## CVE-2026-134882
 A weakness has been identified in TOTOLINK A7100RU 7.4cu.2313_B20191024. This issue affects the function exportOvpn of the file /cgi-bin/cstecgi.cgi of the component CGI Handler. This manipulation of the argument Username causes os command injection. The attack is possible to be carried out remotely.

- [https://github.com/cveForge/CVE-2026-134882](https://github.com/cveForge/CVE-2026-134882) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134882.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134882.svg)


## CVE-2026-134859
 Assimp through 6.0.6 contains a heap out-of-bounds write vulnerability in PLYImporter::LoadFace and PLYImporter::createFromeTriStrip that fails to validate face vertex indices against the vertex count. Attackers can supply a crafted PLY file whose out-of-range indices cause GenVertexNormalsProcess::GenMeshVertexNormals to write normals outside the heap buffer, crashing the application or potentially enabling code execution.

- [https://github.com/cveForge/CVE-2026-134859](https://github.com/cveForge/CVE-2026-134859) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134859.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134859.svg)


## CVE-2026-134850
 A security vulnerability has been detected in aceberg WatchYourLAN up to 2.1.4. Affected by this issue is the function getPortState of the file backend/internal/api/api-network.go of the component Web API. The manipulation of the argument addr leads to server-side request forgery. The attack is possible to be carried out remotely. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/cveForge/CVE-2026-134850](https://github.com/cveForge/CVE-2026-134850) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134850.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134850.svg)


## CVE-2026-134836
 Dashy 4.0.0 before 4.9.12 contains a credential disclosure vulnerability in isLocalRequest that attaches user credentials to lookalike hosts due to prefix-only origin checks. Attackers can lure logged-in users to a crafted ?config= link pointing to a lookalike host, capturing bearer tokens or HTTP auth headers to read configuration and stored API keys, or modify them when the victim is an admin.

- [https://github.com/cveForge/CVE-2026-134836](https://github.com/cveForge/CVE-2026-134836) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134836.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134836.svg)


## CVE-2026-134827
 Lightdash before 3.212.0 contains an insufficiently protected credentials vulnerability in getGitlabInstallationRepoReadAccess that sends the organization GitLab app token to unverified hosts. Project developers can set the dbt connection host_domain to an attacker-controlled server and capture the token when the AI agent reads the repository, gaining access to every reachable repository.

- [https://github.com/cveForge/CVE-2026-134827](https://github.com/cveForge/CVE-2026-134827) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134827.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134827.svg)


## CVE-2026-134815
 simple-git before 4.1.0 contains an argument injection vulnerability that allows attackers to bypass the allowUnsafePack guard by supplying the --exec option to non-push git operations. Attackers who influence arguments passed to listRemote() or raw() can inject --exec for ls-remote, archive, fetch-pack or send-pack to execute commands on the host.

- [https://github.com/cveForge/CVE-2026-134815](https://github.com/cveForge/CVE-2026-134815) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134815.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134815.svg)


## CVE-2026-134814
 binary-parser before 2.3.1 contains a code injection vulnerability that allows attackers controlling parser definitions to inject JavaScript through string-typed options passed unvalidated by Context.generateOption(). Attackers can supply crafted length, lengthInBytes, key, tag, offset, or namely() alias values to execute arbitrary JavaScript in the Node.js process when the parser is compiled.

- [https://github.com/cveForge/CVE-2026-134814](https://github.com/cveForge/CVE-2026-134814) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134814.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134814.svg)


## CVE-2026-134624
 N-able MailAssure (SpamExperts) before 20261121.1943 does not restrict the destination of the LDAP synchronisation connection check performed when a relay is configured. An authenticated API user can cause the server to connect to arbitrary internal hosts and ports, determine which are reachable, and send crafted data to internal services.

- [https://github.com/cveForge/CVE-2026-134624](https://github.com/cveForge/CVE-2026-134624) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134624.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134624.svg)


## CVE-2026-134451
 Dockhand before 1.0.57 contains a privilege escalation vulnerability that allows non-admin users with settings:edit permission to modify OIDC provider configuration due to an improper permission check. Attackers can send a PUT request to /api/auth/oidc/provider-id setting adminClaim to their own OIDC group, gaining full admin access on their next OIDC login.

- [https://github.com/cveForge/CVE-2026-134451](https://github.com/cveForge/CVE-2026-134451) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134451.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134451.svg)


## CVE-2026-134435
 Frappe ERPNext before 15.124.2 and 16.x before 16.50.0 contains a missing authorization vulnerability in an Accounts module endpoint that records bank clearance dates, which checks only a broad role permission before writing to caller-named payment documents. Authenticated Accounts Users can send crafted requests naming payment documents of other companies, outside their User Permissions, or already submitted, to alter clearance dates and compromise bank reconciliation integrity.

- [https://github.com/cveForge/CVE-2026-134435](https://github.com/cveForge/CVE-2026-134435) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134435.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134435.svg)


## CVE-2026-134417
 Frappe ERPNext 13.0.0 before 15.121.4 and 16.x before 16.36.0 contains a missing authorization vulnerability in an Accounts module endpoint that returns uploaded bank statement file content without checking record-level permissions. Authenticated attackers, including portal users or users with no assigned roles, can send crafted requests naming records outside their scope to read full statement file contents.

- [https://github.com/cveForge/CVE-2026-134417](https://github.com/cveForge/CVE-2026-134417) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134417.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134417.svg)


## CVE-2026-134404
 Frappe ERPNext 6.3.0 before 15.124.0 and 16.x before 16.52.0 contains a missing authorization vulnerability in the customer and supplier portal list endpoint, which returns complete selling documents and RFQs without checking permission on the requested records. Authenticated attackers, including portal users or users without roles, can request out-of-scope records to read valuation, margin, and other bidder details.

- [https://github.com/cveForge/CVE-2026-134404](https://github.com/cveForge/CVE-2026-134404) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134404.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134404.svg)


## CVE-2026-134401
 Improper input validation in Variations in Google Chrome prior to 158.0.8127.88 allowed a remote attacker to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Critical)

- [https://github.com/abraxas/cve-2026-134401-chrome-variations-http-seed](https://github.com/abraxas/cve-2026-134401-chrome-variations-http-seed) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-134401-chrome-variations-http-seed.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-134401-chrome-variations-http-seed.svg)


## CVE-2026-134393
 Frappe ERPNext 10.1.41 before 15.122.0 and 16.x before 16.50.0 contains a missing authorization vulnerability in a Manufacturing module endpoint that replaces BOMs without checking whether the caller may modify either BOM or the affected assemblies. Authenticated users who can create a BOM Update Log can send a crafted request naming two BOMs to replace the first with the second in every assembly site-wide.

- [https://github.com/cveForge/CVE-2026-134393](https://github.com/cveForge/CVE-2026-134393) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134393.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134393.svg)


## CVE-2026-134367
 pypdf 2.4.2 before 7.0.0 contains a resource exhaustion vulnerability in its handling of XFA forms that allows attackers to cause excessive memory consumption. Attackers can supply a crafted PDF containing XFA forms with many small fields so that loading the forms consumes large amounts of memory, causing a denial of service.

- [https://github.com/cveForge/CVE-2026-134367](https://github.com/cveForge/CVE-2026-134367) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134367.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134367.svg)


## CVE-2026-134337
 ArcadeDB native-image server builds 26.8.1 before 26.11.1 contain an authorization bypass vulnerability that allows authenticated clients to perform writes through read-only query paths by nesting statements in SELECT. Missing reflection metadata leaves SqlAstInspector with an empty AST, letting INSERT in projections or LET clauses persist via the query endpoint, MCP read-only mode, and HA follower routing.

- [https://github.com/cveForge/CVE-2026-134337](https://github.com/cveForge/CVE-2026-134337) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134337.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134337.svg)


## CVE-2026-134325
 ArcadeDB before 26.11.1 contains a denial of service vulnerability in the Redis protocol handler, which neither replies to nor closes a pre-authentication connection when it receives an array whose first element is not a string. Unauthenticated attackers can resend such an array just within the 30-second socket idle timeout to hold connections open indefinitely and exhaust RedisNetworkExecutor threads.

- [https://github.com/cveForge/CVE-2026-134325](https://github.com/cveForge/CVE-2026-134325) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134325.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134325.svg)


## CVE-2026-134292
 SurrealDB 1.0.0 before 4.0.0 contains a capability check bypass in its embedded JavaScript scripting engine, where the surrealdb.functions bridge calls the internal fnc::synchronous() and fnc::asynchronous() dispatchers without enforcing function capability checks. Authenticated users denied access to built-in functions in SurrealQL can execute them by calling them through surrealdb.functions from embedded JavaScript.

- [https://github.com/cveForge/CVE-2026-134292](https://github.com/cveForge/CVE-2026-134292) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134292.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134292.svg)


## CVE-2026-134291
 SurrealDB 3.0.0 before 4.0.0 contains a path traversal vulnerability in its filesystem storage bucket that only canonicalizes the bucket root, not descendant symlinks. Attackers can reference paths through a pre-existing symlink inside the bucket that pass the lexical prefix check, reading and writing files across the host filesystem.

- [https://github.com/cveForge/CVE-2026-134291](https://github.com/cveForge/CVE-2026-134291) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134291.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134291.svg)


## CVE-2026-134287
 OpenRemote core before 1.34.0 contains an authentication bypass vulnerability in UserAssetProvisioningMQTTHandler that allows unauthenticated attackers to impersonate provisioned devices without proof of private key possession. Attackers can publish a known device's public certificate to the provisioning request topic, authenticating their anonymous MQTT connection as the device's service account to read and modify assets.

- [https://github.com/cveForge/CVE-2026-134287](https://github.com/cveForge/CVE-2026-134287) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134287.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134287.svg)


## CVE-2026-134250
 Grav Form plugin 1.1.0 before 9.1.40 contains a stored cross-site scripting vulnerability in Form::uploadFiles(), which sanitizes SVG only when a file's last extension is .svg and accepts markup under unrecognized extensions. Anonymous attackers can upload files like drawing.svg.foo through public any-type upload forms, running script in an administrator's session when opened, enabling super-admin creation on Grav 2.x with Admin2.

- [https://github.com/cveForge/CVE-2026-134250](https://github.com/cveForge/CVE-2026-134250) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134250.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134250.svg)


## CVE-2026-134246
 SiYuan 3.6.0 before 3.6.2 and 3.7.3 before 3.8.10 contains a missing authorization vulnerability in the /api/block/getDOMText endpoint, which renders caller-supplied DOM without checking publish access for referenced image paths. When publish authentication is disabled, anonymous visitors can submit DOM referencing a known unpublished, non-encrypted asset path to retrieve its already-cached OCR text.

- [https://github.com/cveForge/CVE-2026-134246](https://github.com/cveForge/CVE-2026-134246) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-134246.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-134246.svg)


## CVE-2026-133993
 A security flaw has been discovered in D-Link DIR-600L 2.17b02. This affects the function FUN_0040efb0 of the file gena.cgi of the component GENA Subscription Handler. Performing a manipulation of the argument service results in stack-based buffer overflow. The attack is possible to be carried out remotely. The exploit has been released to the public and may be used for attacks.

- [https://github.com/cveForge/CVE-2026-133993](https://github.com/cveForge/CVE-2026-133993) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133993.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133993.svg)


## CVE-2026-133983
 A vulnerability was detected in eigent-ai eigent up to 1.0.2. Affected by this vulnerability is an unknown functionality of the file backend/app/controller/chat_controller.py of the component Local Agent Control API. Performing a manipulation results in missing authentication. The attack may be initiated remotely. Upgrading to version 1.0.3 addresses this issue. The patch is named 59f43afcb1b0ba7b2de8c65d585124f196c4aa17. It is recommended to upgrade the affected component.

- [https://github.com/cveForge/CVE-2026-133983](https://github.com/cveForge/CVE-2026-133983) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133983.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133983.svg)


## CVE-2026-133968
 monailabel (aka MONAI Label) before 0.8.6 allows directory traversal, with resultant remote code execution, via the image parameter to the PUT /datastore/image endpoint, as exploited in the wild starting in September 2026.

- [https://github.com/googlesky/CVE-2026-133968](https://github.com/googlesky/CVE-2026-133968) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133968.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133968.svg)
- [https://github.com/foxcornlab/monai-label-scanner](https://github.com/foxcornlab/monai-label-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/monai-label-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/monai-label-scanner.svg)


## CVE-2026-133949
Upgrading to a secure version of pip should be done either by first upgrading Python to a version that rejects the compromised intermediates (CVE-2026-115557) or use hash pinning with a known-secure version of pip. pip is not vulnerable when using a Python version that rejects the compromised certificates. See the references below for more information.

- [https://github.com/cveForge/CVE-2026-133949](https://github.com/cveForge/CVE-2026-133949) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133949.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133949.svg)


## CVE-2026-133780
The loader no longer evaluates comment content as JavaScript. It now parses each comment as an object expression using a real JavaScript parser and extracts only plain literal values. Any non-literal value, such as a function call, an identifier, or a sequence expression, is rejected and reported as a build error instead of being executed. Legitimate option values like 'lazy' and 'eager' continue to work without any changes required on the user's side.

- [https://github.com/googlesky/CVE-2026-133780](https://github.com/googlesky/CVE-2026-133780) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-133780.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-133780.svg)


## CVE-2026-133680
 A vulnerability was found in D-Link DCS-935L 1.10.01. This affects the function loginRouter of the file web/cgi-bin/localrecording/setconf.cgi of the component Local Recording CGI. Performing a manipulation of the argument account/password results in os command injection. Remote exploitation of the attack is possible. The exploit has been made public and could be used.

- [https://github.com/cveForge/CVE-2026-133680](https://github.com/cveForge/CVE-2026-133680) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133680.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133680.svg)


## CVE-2026-133648
Affected versions: Flowintel prior to 4.1.0.

- [https://github.com/cveForge/CVE-2026-133648](https://github.com/cveForge/CVE-2026-133648) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133648.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133648.svg)


## CVE-2026-133323
 A vulnerability in the Audio, Web, and Video Conferencing (AWV) component of Mitel MiCollab through 10.3 (10.3.0.18) could allow an unauthenticated attacker to conduct a blind command injection attack due to insufficient parameter sanitization. A successful exploit could allow an attacker to execute arbitrary commands within the context of the system. This is MTLVULN-1864.

- [https://github.com/cveForge/CVE-2026-133323](https://github.com/cveForge/CVE-2026-133323) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-133323.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-133323.svg)


## CVE-2026-133113
 Gogs through 0.14.4 contains an authorization bypass vulnerability that allows collaborators with write access to push to protected branches by merging pull requests. Because MergePullRequest skips branch protection checks and PullRequest.Merge omits hook environment variables, attackers can merge commits into branches restricted to allowlisted users.

- [https://github.com/z3r0s6/gogs-protected-branch-bypass-CVE-2026-133113](https://github.com/z3r0s6/gogs-protected-branch-bypass-CVE-2026-133113) :  ![starts](https://img.shields.io/github/stars/z3r0s6/gogs-protected-branch-bypass-CVE-2026-133113.svg) ![forks](https://img.shields.io/github/forks/z3r0s6/gogs-protected-branch-bypass-CVE-2026-133113.svg)


## CVE-2026-132825
 Ruby before 3.3.14, 3.4.13, and 4.0.10 has a heap-based buffer overflow during case conversion. One byte can be written outside a buffer for, for example, ISO-8859-1 or Windows-1252.

- [https://github.com/googlesky/CVE-2026-132825](https://github.com/googlesky/CVE-2026-132825) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-132825.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-132825.svg)


## CVE-2026-132660
From PEM 10.6.1, these functions run with a fixed search_path.

- [https://github.com/cveForge/CVE-2026-132660](https://github.com/cveForge/CVE-2026-132660) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-132660.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-132660.svg)


## CVE-2026-132659
From PEM 10.6.1, PEM agents can no longer create jobs or change job definitions or job steps.

- [https://github.com/cveForge/CVE-2026-132659](https://github.com/cveForge/CVE-2026-132659) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-132659.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-132659.svg)


## CVE-2026-132658
From PEM 10.6.1, PEM agents no longer hold these roles.

- [https://github.com/cveForge/CVE-2026-132658](https://github.com/cveForge/CVE-2026-132658) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-132658.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-132658.svg)


## CVE-2026-132079
Users are recommended to upgrade to version 0.10.0, which fixes the issue. Tokens that an earlier version created keep their long expiry on the server. Delete those tokens and create new ones.

- [https://github.com/cveForge/CVE-2026-132079](https://github.com/cveForge/CVE-2026-132079) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-132079.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-132079.svg)


## CVE-2026-131914
 Deserialization of untrusted data in double-submit cookie vs. form field validation in Idunno.AntiCsrf versions through 0.9.1 Beta on ASP.NET allows remote unauthenticated attackers to execute code via object injection

- [https://github.com/dinosn/cve-2026-131914-poc](https://github.com/dinosn/cve-2026-131914-poc) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-131914-poc.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-131914-poc.svg)
- [https://github.com/l0lsec/CVE-2026-131914](https://github.com/l0lsec/CVE-2026-131914) :  ![starts](https://img.shields.io/github/stars/l0lsec/CVE-2026-131914.svg) ![forks](https://img.shields.io/github/forks/l0lsec/CVE-2026-131914.svg)
- [https://github.com/Hakchandara/CVE-2026-131914](https://github.com/Hakchandara/CVE-2026-131914) :  ![starts](https://img.shields.io/github/stars/Hakchandara/CVE-2026-131914.svg) ![forks](https://img.shields.io/github/forks/Hakchandara/CVE-2026-131914.svg)
- [https://github.com/abraxas/cve-2026-131914-idunno-anticsrf-deserialization](https://github.com/abraxas/cve-2026-131914-idunno-anticsrf-deserialization) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-131914-idunno-anticsrf-deserialization.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-131914-idunno-anticsrf-deserialization.svg)


## CVE-2026-130778
 Incus before 7.6.0 contains an authentication bypass vulnerability that allows remote attackers to authenticate as any trusted certificate by appending its public certificate to their presented TLS client chain. Attackers can append the server's or a cluster member's certificate to gain cluster-level access, bypass authorization, modify trust store entries, and influence scriptlet-based authorization decisions.

- [https://github.com/cveForge/CVE-2026-130778](https://github.com/cveForge/CVE-2026-130778) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-130778.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-130778.svg)


## CVE-2026-130453
 OpenWire protocol dissector crash in 4.6.0 to 4.6.9 and 4.4.0 to 4.4.19 allows denial of service

- [https://github.com/googlesky/CVE-2026-130453](https://github.com/googlesky/CVE-2026-130453) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-130453.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-130453.svg)


## CVE-2026-130007
 k8s-mcp-server manages Kubernetes clusters through the Model Context Protocol. Prior to 1.1.0, SERVER_MODE defaults to SSE, with the listener on 0.0.0.0:8080, but main.go creates the SSE server without an authentication option or context function. The GET /sse handler creates a sessionId that is only a correlation value, and the POST /message handler accepts a loadable sessionId without an authorization or Origin check before dispatching tools/call; consequently, any client able to reach the port can enumerate and invoke registered Kubernetes tools without credentials. Read-only mode is disabled by default, leaving write-capable Kubernetes tools available to run with the server's configured cluster privileges. This issue is fixed in version 1.1.0.

- [https://github.com/abraxas/cve-2026-130007-k8smcp-sse-noauth](https://github.com/abraxas/cve-2026-130007-k8smcp-sse-noauth) :  ![starts](https://img.shields.io/github/stars/abraxas/cve-2026-130007-k8smcp-sse-noauth.svg) ![forks](https://img.shields.io/github/forks/abraxas/cve-2026-130007-k8smcp-sse-noauth.svg)


## CVE-2026-129991
 Dokploy is a free, self-hostable Platform as a Service (PaaS). Prior to 0.31.1, the backup prefix field is only checked for a nonempty value, and normalizeS3Path preserves shell metacharacters before the prefix is interpolated into rclone upload and retention-cleanup command strings. An authenticated organization member with backup permission for a service can execute arbitrary commands as root on the Dokploy host or configured remote server when a PostgreSQL, MySQL, MariaDB, MongoDB, libSQL, Compose, or web-server backup runs manually, on schedule, or performs retention cleanup. This issue is fixed in version 0.31.1.

- [https://github.com/cveForge/CVE-2026-129991](https://github.com/cveForge/CVE-2026-129991) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129991.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129991.svg)


## CVE-2026-129987
 Dokploy is a free, self-hostable Platform as a Service (PaaS). Prior to 0.31.1, the database password validation used by the MySQL, PostgreSQL, MariaDB, MongoDB, and Redis change-password procedures permits backticks, and the procedures interpolate attacker-controlled passwords into Bash command strings. An authenticated user who can update a database password can trigger command substitution before the database command runs, resulting in arbitrary operating-system command execution with the Dokploy process privileges, which are typically root. This issue is fixed in version 0.31.1.

- [https://github.com/cveForge/CVE-2026-129987](https://github.com/cveForge/CVE-2026-129987) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129987.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129987.svg)


## CVE-2026-129975
 A flaw was found in gpgme. When processing crafted input, an early return following memory reallocation can leave internal buffer pointers referencing previously freed memory, resulting in a double-free condition during cleanup. A remote attacker could exploit this vulnerability to corrupt process memory, potentially leading to arbitrary code execution or a Denial of Service (DoS) crash.

- [https://github.com/googlesky/CVE-2026-129975](https://github.com/googlesky/CVE-2026-129975) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129975.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129975.svg)


## CVE-2026-129837
 A flaw was found in rsyslog. A remote, unauthenticated attacker can cause a Denial of Service (DoS) by sending a specially crafted log message with an unusual timestamp. When the service processes this message using weekday formatting templates, an out-of-bounds memory read occurs, causing the application to crash.

- [https://github.com/cveForge/CVE-2026-129837](https://github.com/cveForge/CVE-2026-129837) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129837.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129837.svg)


## CVE-2026-129713
Authentication is not required to exploit this vulnerability.

- [https://github.com/cveForge/CVE-2026-129713](https://github.com/cveForge/CVE-2026-129713) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129713.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129713.svg)


## CVE-2026-129705
This can be mitigated by following the documented requirements for PROXY listeners: It is very important that only trusted proxies are allowed to connect to any listener using the PROXY protocol, and that clients are not allowed to connect to the listener at all.

- [https://github.com/cveForge/CVE-2026-129705](https://github.com/cveForge/CVE-2026-129705) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-129705.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-129705.svg)


## CVE-2026-129514
This issue affects hex.pm: from 2016-02-23 before 2026-11-23; hexpm/hexpm: from ab1bbcef7cc8395d1056d3b1aa6a174353492d59 before 379b0a29bcc95164249f38ad7d772a37a8ff9533.

- [https://github.com/hoarseprairie/CVE-2026-129514-Poc](https://github.com/hoarseprairie/CVE-2026-129514-Poc) :  ![starts](https://img.shields.io/github/stars/hoarseprairie/CVE-2026-129514-Poc.svg) ![forks](https://img.shields.io/github/forks/hoarseprairie/CVE-2026-129514-Poc.svg)


## CVE-2026-129496
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/googlesky/CVE-2026-129496](https://github.com/googlesky/CVE-2026-129496) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129496.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129496.svg)


## CVE-2026-128981
NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/cveForge/CVE-2026-128981](https://github.com/cveForge/CVE-2026-128981) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-128981.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-128981.svg)


## CVE-2026-128138
 NLTK (Natural Language Toolkit) is a suite of open source Python modules, data sets, and tutorials supporting research and development in Natural Language Processing. From 3.10.3 until 3.10.4, the NLTK 3.10.3 JVM hardening validates Java launcher tokens in the options channel but appends the caller-controlled cmd sequence without requiring its first token to be a main class. Supplying -jar or an @argfile through nltk.internals.java or StanfordSegmenter.java_class can therefore execute attacker-selected Java bytecode without the unsafe-JAR opt-in. This issue is fixed in version 3.10.4.

- [https://github.com/cveForge/CVE-2026-128138](https://github.com/cveForge/CVE-2026-128138) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-128138.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-128138.svg)


## CVE-2026-127224
 GFI HelpDesk before 4.99.13 contains an SQL injection vulnerability in the archiver export feature that allows authenticated attackers with administrator privileges to execute arbitrary SQL queries by supplying crafted itemid[] array values to /admin/index.php?/archiver/Manager/ExportAll. The Controller_Manager.ExportAll() method joins the itemid values with implode() and GetWhere() concatenates them into an IN() clause without sanitization or parameterization, and DumpTables() executes the resulting query against each ticket-related table, allowing attackers to read or modify database contents.

- [https://github.com/cveForge/CVE-2026-127224](https://github.com/cveForge/CVE-2026-127224) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-127224.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-127224.svg)


## CVE-2026-126714
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/cybervidhi-192/phpAfterShell-CVE-2026-126714](https://github.com/cybervidhi-192/phpAfterShell-CVE-2026-126714) :  ![starts](https://img.shields.io/github/stars/cybervidhi-192/phpAfterShell-CVE-2026-126714.svg) ![forks](https://img.shields.io/github/forks/cybervidhi-192/phpAfterShell-CVE-2026-126714.svg)
- [https://github.com/im0xfay/CVE-2026-PHP-SESSION-CHAIN](https://github.com/im0xfay/CVE-2026-PHP-SESSION-CHAIN) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-PHP-SESSION-CHAIN.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-PHP-SESSION-CHAIN.svg)


## CVE-2026-126708
 In Eclipse Mosquitto versions 2.0.0 to 2.0.22 and 2.1.0 to 2.1.2, the return value of password hash functions for sha512-pbkdf2 and legacy sha512 were not checked. Starting with OpenSSL 4.0, sha512-pbkdf2 hashing will fail when using the FIPS provider for passwords shorter than 8 characters. This has the effect that newly created passwords would match against any other password with fewer than 8 characters.

- [https://github.com/cveForge/CVE-2026-126708](https://github.com/cveForge/CVE-2026-126708) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-126708.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-126708.svg)


## CVE-2026-126054
This vulnerability was patched on 10 October 2026, and no customer action is needed.

- [https://github.com/cveForge/CVE-2026-126054](https://github.com/cveForge/CVE-2026-126054) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-126054.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-126054.svg)


## CVE-2026-125294
 The Nexter Blocks Pro plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 5.0.10 via the `tpgb_ajax_register_user()` function. This is due to a byte-level denylist on the `tpgb_acf_key[]` and `tpgb_acf[]` parameters that fails to block Unicode look-alike characters — such as U+1E87 and U+00E7 in a key like `ẇp_çapabilities` — whose UTF-8 byte sequences do not match any ASCII-based pattern check, while the database's default accent-insensitive collation (`utf8mb4_unicode_ci` / `utf8mb4_0900_ai_ci`) treats the decorated key as equivalent to the canonical `wp_capabilities` row, causing `update_user_meta()` to overwrite the newly registered user's role with `administrator`. This makes it possible for unauthenticated attackers to register a new account bearing the full Administrator role, gaining complete control over the WordPress site including the ability to install plugins, modify files, and execute arbitrary code. The nonce required by the handler is publicly emitted on any page containing the tp-login-register block, making the full exploit chain — nonce retrieval, a single crafted registration POST, and the plugin's own `autologin` flow — trivially reachable on any default install where user registration is enabled. Successful exploitation causes the attacker's own account to receive the complete Administrator role.

- [https://github.com/cveForge/CVE-2026-125294](https://github.com/cveForge/CVE-2026-125294) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-125294.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-125294.svg)


## CVE-2026-124216
 The Orphans plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'comment' parameter in all versions up to, and including, 3.4.5 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. Exploitation requires a two-step comment chain: a benign first comment must be approved under a given name and email so that WordPress's comment_previously_approved mechanism auto-publishes the attacker's payload comment without moderation.

- [https://github.com/cveForge/CVE-2026-124216](https://github.com/cveForge/CVE-2026-124216) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-124216.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-124216.svg)


## CVE-2026-123210
 Joomla! Core - [20261107] - Core - Insufficient file extension checks in com_media rename and copy actions in Joomla 4.0.0-5.4.10, 6.0.0-6.2.0 - The rename and copy actions of the local media adapter only validate the final file extension, allowing files with a blocked extension in their name.

- [https://github.com/jasonbernier/CVE-2026-123210](https://github.com/jasonbernier/CVE-2026-123210) :  ![starts](https://img.shields.io/github/stars/jasonbernier/CVE-2026-123210.svg) ![forks](https://img.shields.io/github/forks/jasonbernier/CVE-2026-123210.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/cveForge/CVE-2026-123158](https://github.com/cveForge/CVE-2026-123158) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-123158.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-123158.svg)


## CVE-2026-123039
 The Gaia OS DynamicCLI daemon runs as root and listens on a world-writable local socket (/tmp/dynamic_socket) without authenticating connecting processes. An authenticated local user can send a command to the socket and have it executed as root.

- [https://github.com/cveForge/CVE-2026-123039](https://github.com/cveForge/CVE-2026-123039) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-123039.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-123039.svg)


## CVE-2026-123010
 @twilio-labs/netlify-okta-auth through 1.0.2 relies on an unverified iss claim. This affects an outbound HTTP request to retrieve a public signing key. There may be other impacts in a misconfiguration where oktaUrl isn't set.

- [https://github.com/Ahmedhassanelf/CVE-2026-123010-Security-Researcher-Ahmed-Hassan-Elfekiry](https://github.com/Ahmedhassanelf/CVE-2026-123010-Security-Researcher-Ahmed-Hassan-Elfekiry) :  ![starts](https://img.shields.io/github/stars/Ahmedhassanelf/CVE-2026-123010-Security-Researcher-Ahmed-Hassan-Elfekiry.svg) ![forks](https://img.shields.io/github/forks/Ahmedhassanelf/CVE-2026-123010-Security-Researcher-Ahmed-Hassan-Elfekiry.svg)


## CVE-2026-121481
The affected code is outside the FIPS module boundary.

- [https://github.com/cveForge/CVE-2026-121481](https://github.com/cveForge/CVE-2026-121481) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-121481.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-121481.svg)


## CVE-2026-121018
 The affected products insufficiently restrict runtime-supplied visualization commands, allowing local functionality on the engineering workstation to be invoked, if a user is both logged in to a CODESYS Control runtime and operates a visualization. An unauthenticated remote attacker controlling a malicious runtime and tricking a user to trust it, or performing a man-in-the-middle attack on the communication between the CODESYS Control runtime and the engineering workstation, may cause arbitrary code execution on the engineering workstation.

- [https://github.com/cveForge/CVE-2026-121018](https://github.com/cveForge/CVE-2026-121018) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-121018.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-121018.svg)


## CVE-2026-121016
 The affected products insufficiently restrict runtime-supplied visualization data, allowing local program execution on the engineering workstation, if a user is both logged in to a CODESYS Control runtime and operates a visualization. An unauthenticated remote attacker controlling a malicious runtime and tricking a user to trust it, or performing a man-in-the-middle attack on the communication between the CODESYS Control runtime and the engineering workstation, may cause arbitrary code execution on the engineering workstation.

- [https://github.com/cveForge/CVE-2026-121016](https://github.com/cveForge/CVE-2026-121016) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-121016.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-121016.svg)


## CVE-2026-120787
 Improper certificate validation in Microsoft Office PowerPoint allows an unauthorized attacker to execute code over a network.

- [https://github.com/cveForge/CVE-2026-120787](https://github.com/cveForge/CVE-2026-120787) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-120787.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-120787.svg)


## CVE-2026-120777
 Incorrect authorization in Azure Managed Service Identity allows an authorized attacker to elevate privileges over a network.

- [https://github.com/cveForge/CVE-2026-120777](https://github.com/cveForge/CVE-2026-120777) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-120777.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-120777.svg)


## CVE-2026-120676
 The Forminator Forms – Contact Form, Payment Form & Custom Form Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'upload-1 (the File Upload field's element_id)' parameter in all versions up to, and including, 1.58.4 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This vulnerability is an incomplete fix for CVE-2024-1794; exploitation requires that the Forminator form's File Upload field is left at plugin defaults (no 'custom-files' restriction configured) and that the server maps no Content-Type to the .rtx extension — the default behavior of the Debian/Ubuntu Apache package used by the official WordPress Docker image and many shared hosts.

- [https://github.com/cveForge/CVE-2026-120676](https://github.com/cveForge/CVE-2026-120676) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-120676.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-120676.svg)


## CVE-2026-120382
 An improper neutralization of argument delimiters in a command vulnerability in the OAuth API in Synology DiskStation Manager (DSM) before 7.1.1-42962-10, 7.2.1-69057-14, 7.2.2-72806-11, 7.3.2-86009-6, and 7.4.1-90080-2 allows remote attackers to read or write arbitrary files and conduct denial-of-service attacks.

- [https://github.com/cveForge/CVE-2026-120382](https://github.com/cveForge/CVE-2026-120382) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-120382.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-120382.svg)


## CVE-2026-119977
 WordPress Core is vulnerable to Remote Code Execution in versions 4.7 through 7.1.3. This is due to predictable, web-accessible staging paths used during full-package core upgrades. This makes it possible for unauthenticated attackers to execute code on the server during the upgrade window.

- [https://github.com/cveForge/CVE-2026-119977](https://github.com/cveForge/CVE-2026-119977) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-119977.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-119977.svg)


## CVE-2026-119582
This issue affects vSRM: from v14.08.3 before v14.08.5.

- [https://github.com/cveForge/CVE-2026-119582](https://github.com/cveForge/CVE-2026-119582) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-119582.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-119582.svg)


## CVE-2026-119543
This issue affects vSRM: from v14.08.3 before v14.08.5.

- [https://github.com/cveForge/CVE-2026-119543](https://github.com/cveForge/CVE-2026-119543) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-119543.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-119543.svg)


## CVE-2026-118527
 Use of predictable filenames in Ivanti Connect Secure before versions 25.1.1.3 and 22.8R2.6 allows a remote authenticated attacker to upload files with attacker-controlled content to a known location on disk.

- [https://github.com/cveForge/CVE-2026-118527](https://github.com/cveForge/CVE-2026-118527) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-118527.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-118527.svg)


## CVE-2026-118286
 Improper access control in Azure Site Recovery allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/cveForge/CVE-2026-118286](https://github.com/cveForge/CVE-2026-118286) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-118286.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-118286.svg)


## CVE-2026-118285
 Server-side request forgery in Azure Machine Learning allows an authorized attacker to elevate privileges over a network.

- [https://github.com/cveForge/CVE-2026-118285](https://github.com/cveForge/CVE-2026-118285) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-118285.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-118285.svg)


## CVE-2026-118049
 The Tutor LMS – eLearning and online course solution plugin for WordPress is vulnerable to authorization bypass in all versions up to, and including, 4.2.0 This is due to the plugin not properly verifying that a user is authorized to perform an action. This makes it possible for authenticated attackers, with subscriber-level access and above, to permanently delete any comment they authored anywhere on the site — including regular post comments and lesson comments — along with all replies to those comments authored by any other user, including Administrators and Instructors.

- [https://github.com/cveForge/CVE-2026-118049](https://github.com/cveForge/CVE-2026-118049) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-118049.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-118049.svg)


## CVE-2026-117593
This issue affects vSRM: from v14.08.3 before v14.08.5.

- [https://github.com/cveForge/CVE-2026-117593](https://github.com/cveForge/CVE-2026-117593) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-117593.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-117593.svg)


## CVE-2026-116606
 An authentication bypass in Barracuda Email Security Gateway versions earlier than 9.4.0.030 allows an unauthenticated remote attacker to invoke a configuration-import function and restore a crafted, compatible backup archive, resulting in unauthorized modification of the appliance’s global configuration.

- [https://github.com/cveForge/CVE-2026-116606](https://github.com/cveForge/CVE-2026-116606) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-116606.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-116606.svg)


## CVE-2026-116449
 Dell PowerStore SDNAS contains an OS Command Injection vulnerability that could allow an attacker with internal network access to execute arbitrary commands as root on the NAS node.

- [https://github.com/cveForge/CVE-2026-116449](https://github.com/cveForge/CVE-2026-116449) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-116449.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-116449.svg)


## CVE-2026-115899
 An attacker must control pagination data returned by an upstream API or service queried by an existing REST Collector. The Collector must use affected response-based pagination and process the crafted data during a job run. Successful exploitation executes code with the Worker service account's permissions.

- [https://github.com/cveForge/CVE-2026-115899](https://github.com/cveForge/CVE-2026-115899) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-115899.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-115899.svg)


## CVE-2026-115873
 A remote attacker must authenticate with Read Only (GroupRead) access to at least one Worker Group and reach the Leader API. A crafted expression can exploit the nested compiler to bypass expression restrictions and execute code with the Leader service account's permissions.

- [https://github.com/cveForge/CVE-2026-115873](https://github.com/cveForge/CVE-2026-115873) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-115873.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-115873.svg)


## CVE-2026-115731
 Deserialization of untrusted data in the report-processing code of Puppet, as used by Puppet Server, in the affected releases, allows a client that holds any CA-signed agent certificate to execute arbitrary code on the Puppet Server as its service user by submitting a report containing a crafted rich-data type via PUT request. Where the certificate authority autosigns requests without strong verification, an unauthenticated network attacker can obtain such a certificate.

- [https://github.com/cveForge/CVE-2026-115731](https://github.com/cveForge/CVE-2026-115731) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-115731.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-115731.svg)


## CVE-2026-115560
This issue affects PHP versions before 8.2.36, 8.3.* before 8.3.37, 8.4.* before 8.4.28 and 8.5.* before 8.5.13.

- [https://github.com/im0xfay/CVE-2026-PHP-SESSION-CHAIN](https://github.com/im0xfay/CVE-2026-PHP-SESSION-CHAIN) :  ![starts](https://img.shields.io/github/stars/im0xfay/CVE-2026-PHP-SESSION-CHAIN.svg) ![forks](https://img.shields.io/github/forks/im0xfay/CVE-2026-PHP-SESSION-CHAIN.svg)


## CVE-2026-115375
 Incus 7.0.0 before 7.0.2 and 7.1.0 before 7.5.0 contains a path traversal vulnerability that allows clients able to create instances to write files on the host. The flaw stems from unvalidated dependent custom volume names in instance backup index.yaml files. Attackers can import a crafted instance backup with ../ sequences in dependent volume names to create root-owned directories with controlled content, leading to full host compromise.

- [https://github.com/googlesky/CVE-2026-115375](https://github.com/googlesky/CVE-2026-115375) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-115375.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-115375.svg)


## CVE-2026-114938
 Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; Oracle GraalVM for JDK: 17.0.21.0.3 and  21.0.13.0.3; Oracle GraalVM Enterprise Edition: 21.3.20.0.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/googlesky/CVE-2026-114938](https://github.com/googlesky/CVE-2026-114938) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-114938.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-114938.svg)
- [https://github.com/devkirgantenk/patched_ptero](https://github.com/devkirgantenk/patched_ptero) :  ![starts](https://img.shields.io/github/stars/devkirgantenk/patched_ptero.svg) ![forks](https://img.shields.io/github/forks/devkirgantenk/patched_ptero.svg)
- [https://github.com/jburgess-r7/java4shell-elasticsearch-poc](https://github.com/jburgess-r7/java4shell-elasticsearch-poc) :  ![starts](https://img.shields.io/github/stars/jburgess-r7/java4shell-elasticsearch-poc.svg) ![forks](https://img.shields.io/github/forks/jburgess-r7/java4shell-elasticsearch-poc.svg)


## CVE-2026-114713
 The labeled-response module in UnrealIRCd 6.0.0 before 6.2.7.1 does not escape the IRCv3 "label" message tag when echoing it into replies, which allows any user on a network with two or more linked servers to inject server-to-server commands that are executed with server authority.

- [https://github.com/cveForge/CVE-2026-114713](https://github.com/cveForge/CVE-2026-114713) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-114713.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-114713.svg)


## CVE-2026-113824
 Authorization bypass through user-controlled key in Microsoft Clarity allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/cveForge/CVE-2026-113824](https://github.com/cveForge/CVE-2026-113824) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-113824.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-113824.svg)


## CVE-2026-111793
 Openwave Webtop Media Transcoder does not enforce administrator-defined file type restrictions to restrict the file-types to be converted. This may allow an authenticated user to process and convert unintended document types if bypassing the Webmail experience.

- [https://github.com/cveForge/CVE-2026-111793](https://github.com/cveForge/CVE-2026-111793) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-111793.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-111793.svg)


## CVE-2026-111560
 Improper neutralization of shell metacharacters in the timezone configuration field in certain Barracuda appliance products using common Barracuda code allows an authenticated administrator to inject OS commands that execute with root privileges when the crafted timezone value is subsequently processed.

- [https://github.com/cveForge/CVE-2026-111560](https://github.com/cveForge/CVE-2026-111560) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-111560.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-111560.svg)


## CVE-2026-111357
 Ivanti Connect Secure 22.8R2.4 mishandles the manner in which the dsinvoked broker trusts DSCache configuration data, leading to privilege escalation to root, as exploited in the wild in October 2026.

- [https://github.com/cveForge/CVE-2026-111357](https://github.com/cveForge/CVE-2026-111357) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-111357.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-111357.svg)


## CVE-2026-110859
 GitPython before 3.2.0 contains an argument injection vulnerability in Head.checkout() that allows remote attackers to read arbitrary files by supplying a branch name parsed as a git option. Attackers can host a repository whose default branch is named --pathspec-from-file=path, causing cloning applications that check out the active branch to leak file contents through GitCommandError messages.

- [https://github.com/Mahgal/gitpython-rce-check](https://github.com/Mahgal/gitpython-rce-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/gitpython-rce-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/gitpython-rce-check.svg)


## CVE-2026-110858
 GitPython from 3.1.30 before 3.2.0 contains a remote code execution vulnerability in Remote.pull() whose unsafe-option guard inspects only keyword arguments, not the positional refspec. Attackers controlling the refspec can supply --upload-pack=command to execute OS commands as the calling process over local-path or SSH transports.

- [https://github.com/Mahgal/gitpython-rce-check](https://github.com/Mahgal/gitpython-rce-check) :  ![starts](https://img.shields.io/github/stars/Mahgal/gitpython-rce-check.svg) ![forks](https://img.shields.io/github/forks/Mahgal/gitpython-rce-check.svg)


## CVE-2026-110513
Users are recommended to upgrade to version 0.10.0, which fixes the issue.

- [https://github.com/cveForge/CVE-2026-110513](https://github.com/cveForge/CVE-2026-110513) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-110513.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-110513.svg)


## CVE-2026-110264
 An issue has been discovered in GitLab CE/EE affecting all versions from 7.0 before 18.11.13, 19.0 before 19.0.10, 19.1 before 19.1.9, 19.2 before 19.2.9, 19.3 before 19.3.6, 19.4 before 19.4.3, and 19.5 before 19.5.1 that, under certain conditions, could have allowed an unauthenticated user to execute arbitrary code on the GitLab server due to integer overflow when compiling a specially crafted regular expression.

- [https://github.com/cveForge/CVE-2026-110264](https://github.com/cveForge/CVE-2026-110264) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-110264.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-110264.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc](https://github.com/lzz0403/CVE-2026-109618-PHP2Shell-poc) :  ![starts](https://img.shields.io/github/stars/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg) ![forks](https://img.shields.io/github/forks/lzz0403/CVE-2026-109618-PHP2Shell-poc.svg)


## CVE-2026-109490
 Improper neutralization of input during web page generation ('cross-site scripting') in Authentication Methods Portal Extension allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/cveForge/CVE-2026-109490](https://github.com/cveForge/CVE-2026-109490) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-109490.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-109490.svg)


## CVE-2026-109480
 Server-side request forgery in Profile Data Roaming Service (PDRS) allows an authorized attacker to elevate privileges over a network.

- [https://github.com/cveForge/CVE-2026-109480](https://github.com/cveForge/CVE-2026-109480) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-109480.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-109480.svg)


## CVE-2026-108575
 A vulnerability has been found in BerriAI LiteLLM up to 1.94.0. This affects the function get_secret of the file secret_managers/main.py of the component Secret Resolution. The manipulation of the argument api_key leads to improper authorization. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/hakaioffsec/CVE-2026-108574-CVE-2026-108575-POC](https://github.com/hakaioffsec/CVE-2026-108574-CVE-2026-108575-POC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-108574-CVE-2026-108575-POC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-108574-CVE-2026-108575-POC.svg)


## CVE-2026-108574
 A flaw has been found in BerriAI LiteLLM up to 1.95.0. Affected by this issue is the function ui_view_session_spend_logs of the file litellm/proxy/spend_tracking/spend_management_endpoints.py of the component Spend Tracking. Executing a manipulation of the argument session_id can lead to authorization bypass. It is possible to launch the attack remotely. The exploit has been published and may be used. Upgrading to version 1.96.0 can resolve this issue. This patch is called 722d9ffa4f6c5ae15702ab9ab2c5f6bf1688308b. The affected component should be upgraded.

- [https://github.com/hakaioffsec/CVE-2026-108574-CVE-2026-108575-POC](https://github.com/hakaioffsec/CVE-2026-108574-CVE-2026-108575-POC) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-108574-CVE-2026-108575-POC.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-108574-CVE-2026-108575-POC.svg)


## CVE-2026-107904
 Joomla Extension - valorapps.com - Unauthenticated Remote Code Execution in Easy File Uploader  2.9.7 - An unauthenticated remote attacker can upload a PHP-executable file to the Joomla web root with a single multipart POST request, requiring no credentials and no CSRF token.

- [https://github.com/cveForge/CVE-2026-107904](https://github.com/cveForge/CVE-2026-107904) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-107904.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-107904.svg)


## CVE-2026-107654
 The One to one user Chat by WPGuppy plugin for WordPress is vulnerable to generic SQL Injection via the 'userId' parameter in all versions up to, and including, 1.1.6 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database. The plugin's permission callback is trivially bypassed because it validates a JWT that the plugin itself signs using an attacker-supplied value from the guppy_guest_account cookie, and the guest code path (userType=0) skips the get_userdata() check that would confirm the userId corresponds to a real WordPress user.

- [https://github.com/cveForge/CVE-2026-107654](https://github.com/cveForge/CVE-2026-107654) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-107654.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-107654.svg)


## CVE-2026-104126
 JumpServer is an open source bastion host and an operation and maintenance security audit system. Prior to 4.10.17-lts, JumpServer's Ansible-based automation rendering can evaluate attacker-controlled template expressions from users who have permission to create or execute affected automation tasks. Crafted content can invoke sensitive Ansible lookup behavior, including file, pipe, env, and password lookups, within the Ansible execution context, which can disclose files or environment values and may permit limited command execution under the privileges of the automation process. The issue does not provide unauthenticated access or direct access to unrelated JumpServer assets. This issue is fixed in version 4.10.17-lts.

- [https://github.com/cveForge/CVE-2026-104126](https://github.com/cveForge/CVE-2026-104126) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-104126.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-104126.svg)


## CVE-2026-101870
 EUSurvey through 1.6, prior to commit de1145c, contains an authorization bypass vulnerability in the public POST /editcontribution/{code} endpoint that allows unauthenticated attackers to overwrite another respondent's submitted answers. The handler in ContributionController selects the survey and answer set from body parameters by numeric contribution ID and never checks that the private edit code in the URL matches that contribution, so an attacker who knows a contribution ID can replace its saved answers without the respondent's edit link.

- [https://github.com/cveForge/CVE-2026-101870](https://github.com/cveForge/CVE-2026-101870) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-101870.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-101870.svg)


## CVE-2026-101869
 EUSurvey 1.4.4.6738 through 1.6, prior to commit de1145c, contains an SQL injection vulnerability in the public results page GET /publication/{shortname} that allows unauthenticated attackers to infer non-public response data. ReportingService builds a SQL column expression from part of a user-supplied filter parameter name and inserts it directly into the query, so a visitor to any survey that publishes its results can inject boolean conditions and use the presence or absence of public result rows to infer private reporting data, including response data and respondent metadata from other surveys.

- [https://github.com/cveForge/CVE-2026-101869](https://github.com/cveForge/CVE-2026-101869) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-101869.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-101869.svg)


## CVE-2026-101868
 EUSurvey through 1.6, prior to commit 4bf95a3, contains an authorization bypass vulnerability in the GET /preparepublishedcontribution/{id} endpoint that allows unauthenticated attackers to read private responses submitted to published surveys. The contribution PDF handler in ContributionController looks up a response by its sequential database ID and skips the normal response access checks, so attackers can enumerate IDs to retrieve other respondents' answers, including free-text answers that may contain personal data, across surveys.

- [https://github.com/cveForge/CVE-2026-101868](https://github.com/cveForge/CVE-2026-101868) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-101868.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-101868.svg)


## CVE-2026-101867
 EUSurvey through 1.6, prior to commit edb5021, contains an incorrect authorization vulnerability in the GET /settings/shareEdit/{shareId} and POST /settings/shares handlers that allows any authenticated user to read or modify another user's contact share. The ownership check in SettingsController denies access only when a condition is both true and false, so it never denies access, allowing an ordinary account without Contact Management privileges to read the names and email addresses in a share and to rename it, change its recipient or access mode, or replace its contacts.

- [https://github.com/cveForge/CVE-2026-101867](https://github.com/cveForge/CVE-2026-101867) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-101867.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-101867.svg)


## CVE-2026-101866
 EUSurvey through 1.6, prior to commit 118facd, contains an authorization bypass vulnerability in the public POST /runner/draft/runner endpoint that allows unauthenticated attackers to overwrite another participant's saved draft and obtain its private invitation token. The draft save handler in RunnerController and AnswerService loads an existing draft by invitation alone without checking that the submitted survey, participation group and invitation belong together, then replaces the draft's answers, reassigns it to the submitted survey, and returns a resume link containing the private invitation token.

- [https://github.com/cveForge/CVE-2026-101866](https://github.com/cveForge/CVE-2026-101866) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-101866.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-101866.svg)


## CVE-2026-101864
 EUSurvey through 1.6, prior to commit a4161a9, contains a weak password recovery mechanism that allows attackers who obtain a still-valid password-reset link to take over accounts that use a local EUSurvey password. The /auth/reset/ flow checks only the age of a reset code and does not invalidate it after the password is changed, and issuing a newer link leaves earlier links active, so a used or superseded link remains valid for up to 24 hours from issuance and can be reused to set a new password, sign in as the affected user, and lock that user out.

- [https://github.com/cveForge/CVE-2026-101864](https://github.com/cveForge/CVE-2026-101864) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-101864.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-101864.svg)


## CVE-2026-101863
 EUSurvey 1.5.5 through 1.6, prior to commit d5295d5, contains a missing authorization vulnerability in the POST /forms/bulkchange endpoint that allows any authenticated user to take over or delete other users' surveys. SurveyController accepts arbitrary survey IDs and privilege values, and BulkExecutor applies the requested access-right changes or deletion without checking whether the requester can manage those surveys, allowing an ordinary ROLE_USER account to grant itself full control of another user's survey, read its draft and results, edit the form, manage its invitations, or delete it.

- [https://github.com/cveForge/CVE-2026-101863](https://github.com/cveForge/CVE-2026-101863) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-101863.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-101863.svg)


## CVE-2026-101862
 EUSurvey through 1.6, prior to commit 0669a36, contains a path traversal vulnerability in the survey import function that allows authenticated attackers with the Form Manager role to execute arbitrary code on the server. The POST /noform/management/importSurvey endpoint trusts archive entry names when SurveyExportHelper writes imported files through FileService, so a crafted survey archive can write a JSP file outside the survey storage directory into the application directory, where Tomcat executes it with the privileges of the EUSurvey process

- [https://github.com/cveForge/CVE-2026-101862](https://github.com/cveForge/CVE-2026-101862) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-101862.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-101862.svg)


## CVE-2026-99491
desynchronization.

- [https://github.com/ChaYeWuu/XRING-CVE-2026-99491](https://github.com/ChaYeWuu/XRING-CVE-2026-99491) :  ![starts](https://img.shields.io/github/stars/ChaYeWuu/XRING-CVE-2026-99491.svg) ![forks](https://img.shields.io/github/forks/ChaYeWuu/XRING-CVE-2026-99491.svg)
- [https://github.com/qq2770355800/ExtractKit-99491](https://github.com/qq2770355800/ExtractKit-99491) :  ![starts](https://img.shields.io/github/stars/qq2770355800/ExtractKit-99491.svg) ![forks](https://img.shields.io/github/forks/qq2770355800/ExtractKit-99491.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/HHHHanasak1/quest3_98260](https://github.com/HHHHanasak1/quest3_98260) :  ![starts](https://img.shields.io/github/stars/HHHHanasak1/quest3_98260.svg) ![forks](https://img.shields.io/github/forks/HHHHanasak1/quest3_98260.svg)
- [https://github.com/minhmc2007/CVE-2026-98260-My-A55](https://github.com/minhmc2007/CVE-2026-98260-My-A55) :  ![starts](https://img.shields.io/github/stars/minhmc2007/CVE-2026-98260-My-A55.svg) ![forks](https://img.shields.io/github/forks/minhmc2007/CVE-2026-98260-My-A55.svg)


## CVE-2026-96991
 The SchemaEngine AI – AI Schema Markup, Reviews & Rich Snippets for SEO plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Comment Content via WebPage JSON-LD Description in all versions up to, and including, 3.1.3 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. Exploitation requires that the target page renders a core/latest-comments block with the displayExcerpt option enabled, causing comment content to be incorporated into the WebPage JSON-LD description output in wp_head.

- [https://github.com/cveForge/CVE-2026-96991](https://github.com/cveForge/CVE-2026-96991) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-96991.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-96991.svg)


## CVE-2026-93658
 uutils coreutils versions before 0.10.0 apply setuid or setgid mode to install destinations before finalizing ownership changes, allowing privileged users to leave setuid executables owned by the privileged invoker when ownership changes fail. Attackers can execute leftover setuid files with elevated privileges when ownership change operations fail on capability-restricted systems.

- [https://github.com/mohyieddine-kamal/cve-2026-93658-analysis](https://github.com/mohyieddine-kamal/cve-2026-93658-analysis) :  ![starts](https://img.shields.io/github/stars/mohyieddine-kamal/cve-2026-93658-analysis.svg) ![forks](https://img.shields.io/github/forks/mohyieddine-kamal/cve-2026-93658-analysis.svg)


## CVE-2026-85097
 The Bricksforge plugin for WordPress is vulnerable to unauthenticated arbitrary file upload in versions up to, and including, 3.1.8.9. This is due to insufficient validation of the attacker-controlled URL field in the 'temporaryFileUploads' parameter during form submission. An unauthenticated attacker can first obtain a valid nonce via the bricksforge_regenerate_nonce AJAX endpoint, then upload a GIF/PHP polyglot file to the temporary upload directory where MIME type validation is correctly performed. Subsequently, the attacker can submit a form with a crafted 'temporaryFileUploads' parameter where the server-side file path points to the validated GIF file, but the attacker-controlled url field ends with a .php extension. This makes it possible for unauthenticated attackers to upload and execute arbitrary PHP code on the server.

- [https://github.com/Tarangj07/Wordpress-Lab-CVE-2026-85097](https://github.com/Tarangj07/Wordpress-Lab-CVE-2026-85097) :  ![starts](https://img.shields.io/github/stars/Tarangj07/Wordpress-Lab-CVE-2026-85097.svg) ![forks](https://img.shields.io/github/forks/Tarangj07/Wordpress-Lab-CVE-2026-85097.svg)


## CVE-2026-82216
This issue affects vSRM: from 14.08.1 before 14.08.3.

- [https://github.com/cveForge/CVE-2026-82216](https://github.com/cveForge/CVE-2026-82216) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-82216.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-82216.svg)


## CVE-2026-81962
 Incorrect authorization in Azure Machine Learning allows an unauthorized attacker to disclose information over a network.

- [https://github.com/cveForge/CVE-2026-81962](https://github.com/cveForge/CVE-2026-81962) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-81962.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-81962.svg)


## CVE-2026-77918
 Gogs through 0.14.4 contains an information disclosure vulnerability that allows authenticated users to view private forks by querying fork listings without per-fork read checks. Attackers with read access to a private base repository can call GET /api/v1/repos/{owner}/{repo}/forks or the Forks web handler to obtain other users' private fork owners, names, descriptions and clone URLs.

- [https://github.com/z3r0s6/gogs-private-fork-disclosure-CVE-2026-77918](https://github.com/z3r0s6/gogs-private-fork-disclosure-CVE-2026-77918) :  ![starts](https://img.shields.io/github/stars/z3r0s6/gogs-private-fork-disclosure-CVE-2026-77918.svg) ![forks](https://img.shields.io/github/forks/z3r0s6/gogs-private-fork-disclosure-CVE-2026-77918.svg)


## CVE-2026-77423
 JLine is a Java library for handling console input. From 3.0.0 until 3.30.15 and 4.3.1, the JLine built-in less viewer passes user-controlled search and display-filter patterns from getPattern(boolean doDisplayPattern) in builtins/src/main/java/org/jline/builtins/Less.java directly to Java's backtracking regular expression engine and repeatedly applies them to file content. A nested-quantifier expression evaluated against non-matching lines can consume excessive CPU and indefinitely block the session thread, and repeated sessions in Telnet or SSH deployments can exhaust a bounded worker pool. This issue is fixed in versions 3.30.15 and 4.3.1.

- [https://github.com/googlesky/CVE-2026-77423](https://github.com/googlesky/CVE-2026-77423) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77423.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77423.svg)


## CVE-2026-77331
 memtomem-stm is a short-term memory proxy gateway with proactive memory surfacing for AI agents. From 0.1.2 until 0.1.34, concurrent surfacing RPC failures can start more than one reconnect for the same dirty session because concurrent LTM recovery is not uniquely owned by a session generation. Cancellation during a post-reconnect retry can also leave the replacement transport reusable after an interrupted protocol exchange, causing session-state integrity loss or local service degradation. The duplicate-reconnect subcase was introduced in 0.1.24, while the cancellation-recovery subcase affects the broader listed range. This issue is fixed in version 0.1.34.

- [https://github.com/googlesky/CVE-2026-77331](https://github.com/googlesky/CVE-2026-77331) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-77331.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-77331.svg)


## CVE-2026-70305
 Improper neutralization of input during web page generation ('cross-site scripting') in Azure Portal allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/cveForge/CVE-2026-70305](https://github.com/cveForge/CVE-2026-70305) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-70305.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-70305.svg)


## CVE-2026-70193
 Improper limitation of a pathname to a restricted directory ('path traversal') in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.

- [https://github.com/cveForge/CVE-2026-70193](https://github.com/cveForge/CVE-2026-70193) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-70193.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-70193.svg)


## CVE-2026-69899
 Authentication bypass by spoofing in Azure DevTest Labs allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/cveForge/CVE-2026-69899](https://github.com/cveForge/CVE-2026-69899) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-69899.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-69899.svg)


## CVE-2026-69437
 Missing authorization in Azure AI Foundry allows an unauthorized attacker to disclose information over a network.

- [https://github.com/cveForge/CVE-2026-69437](https://github.com/cveForge/CVE-2026-69437) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-69437.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-69437.svg)


## CVE-2026-65817
 Improper neutralization of special elements used in an os command ('os command injection') in Azure Managed Instance for Apache Cassandra allows an unauthorized attacker to execute code over an adjacent network.

- [https://github.com/cveForge/CVE-2026-65817](https://github.com/cveForge/CVE-2026-65817) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-65817.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-65817.svg)


## CVE-2026-65320
 fastcore through 2.2.44 contains a path traversal vulnerability in the fastcore.xtras.untar_dir() archive extraction helper that allows attackers who supply a crafted tar archive to write files outside the intended extraction directory. The internal _unpack() function passes the archive to shutil.unpack_archive() without a tar extraction filter, member path validation, or a containment check, so archive members with absolute paths or ../ traversal sequences are written to arbitrary locations writable by the application process when running on Python versions before 3.14. Applications that extract untrusted archives with untar_dir() can have application files, configuration, or importable code overwritten, which can lead to code execution, data modification, or denial of service.

- [https://github.com/rahulreddykarne/CVE-2026-65320-fastcore](https://github.com/rahulreddykarne/CVE-2026-65320-fastcore) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/CVE-2026-65320-fastcore.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/CVE-2026-65320-fastcore.svg)


## CVE-2026-64855
 soapbar is a SOAP library for Python — client, server, and WSDL handling. Prior to version 0.13.0, verify_envelope_bsp() derived its trust anchor from the message it was verifying. It read the X.509 certificate out of the caller-untrusted wsse:BinarySecurityToken, validated only that certificate's not-before / not-after dates, and then verified the signature against that same certificate. There was no CA-chain validation, no issuer/subject allowlist, and no pinning. A successful verify_envelope_bsp() therefore proved only that the envelope was signed by whoever supplied the embedded certificate — never that it was signed by a trusted party. An attacker who mints their own certificate, signs a forged envelope, and embeds that certificate in the token passes verification. Any consumer that treats a successful BSP verification as authentication can be impersonated (signature forgery / authentication bypass). verify_envelope() (which pins a caller-supplied x509_cert) was not affected — the flaw was specific to the BSP variant whose trust anchor came from the message. This issue has been patched in version 0.13.0.

- [https://github.com/googlesky/CVE-2026-64855](https://github.com/googlesky/CVE-2026-64855) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-64855.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-64855.svg)


## CVE-2026-63492
 This CVE is a duplicate of another CVE.

- [https://github.com/googlesky/CVE-2026-63492](https://github.com/googlesky/CVE-2026-63492) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63492.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63492.svg)


## CVE-2026-63476
 isomorphic-git is a pure JavaScript implementation of Git for Node.js and browsers. Prior to 1.38.6, isomorphic-git reads a server-controlled targetSize while applying a packfile delta in src/utils/applyDelta.js and passes it without a bound to Buffer.alloc(targetSize). A malicious or man-in-the-middle-controlled remote can send one delta header that causes git.clone() or git.fetch() to allocate approximately 2 GB before validating the actual delta output. GitPackIndex.fromPack swallows the later size-mismatch error, so a host with sufficient memory may retain the resource waste without a visible failure, while containers, serverless functions, and small virtual machines may terminate. Node.js heap limits do not mitigate the off-heap Buffer allocation. This issue is fixed in version 1.38.6.

- [https://github.com/googlesky/CVE-2026-63476](https://github.com/googlesky/CVE-2026-63476) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63476.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63476.svg)


## CVE-2026-63410
 secp256k1-native is a native C secp256k1 implementation for Ruby. In affected native builds, native constant-time scalar multiplication through `Point#mul` or `scalar_multiply_ct` can leak timing information about a secret scalar when compiled by a toolchain that reconstructs branchless selection into a branch. The `Montgomery ladder` uses `uint256_select` with an all-zeros or all-ones mask, but affected GCC builds at `-O2` recover the original condition and emit secret-dependent `je` or `jne` jumps whose timing correlates with scalar bits. This defeats the assumption behind the 0.17.0 `jp_add_internal` infinity-branch fix. A consumer must multiply a secret private key or nonce in a context where an attacker can observe timing; repeated measurements can statistically recover scalar bits. The defect is in the compiled binary, so source review or `ctgrind` on a non-reconstructing toolchain may miss it. GCC 14.3.0, 15.1.0, and 15.2.0 reproduced the branch reconstruction, and `extconf.rb` appends `-O2`. Tested GCC versions through 12.4.0 used bitwise operations and GCC 13.3.0 used constant-time `cmov`; the pure-Ruby path is not affected by this flaw and separately makes no constant-time claim. GCC 16 and clang were untested, and point releases, targets, and flag combinations were not exhaustively bisected. `Earlier pre-0.17.0 versions had different constant-time issues rather than this introduced select idiom.` Version 0.18.0 contains the verified fix. The advisory's broad pre-0.18.0 guidance also covers earlier, different constant-time issues; whether this CVE groups those issues or only the select idiom introduced in 0.17.0 remains unresolved.

- [https://github.com/googlesky/CVE-2026-63410](https://github.com/googlesky/CVE-2026-63410) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63410.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63410.svg)


## CVE-2026-63402
 i18next is an internationalization framework for JavaScript. Prior to version 26.3.4, `deepExtend` in `src/utils.js` checks property existence with the in operator and recurses into inherited built-ins reached through `Object.prototype`. An application must explicitly pass attacker-controlled resource data to `addResourceBundle(lng, ns, data, deep, overwrite)` with both `deep: true` and `overwrite: true`. Source keys such as `hasOwnProperty`, `toString` and `valueOf` can then select shared inherited built-in function objects, and a nested value can overwrite a property of those objects process-wide. For example, making `Object.prototype.hasOwnProperty.call` non-callable causes subsequent uses, including i18next internals, to throw TypeError, resulting in unrecoverable denial of service and limited integrity impact. The `__proto__`/`constructor` guard does not prevent this mechanism because the corruption target is an inherited built-in function rather than the prototype object itself. Default calls without deep merging or with overwrite falsy are unaffected, and no standard i18next backend or integration uses the vulnerable configuration. This issue is distinct from the setPath/key-walking prototype-pollution flaws in i18next-fs-backend (CVE-2026-48713) and i18next-http-middleware (CVE-2026-48714). This issue is fixed in version 26.3.4.

- [https://github.com/googlesky/CVE-2026-63402](https://github.com/googlesky/CVE-2026-63402) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-63402.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-63402.svg)


## CVE-2026-62841
 Improper authentication in Azure Event Grid allows an unauthorized attacker to elevate privileges over a network.

- [https://github.com/cveForge/CVE-2026-62841](https://github.com/cveForge/CVE-2026-62841) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-62841.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-62841.svg)


## CVE-2026-62337
 SNARK Verifier is a generic (S)NARK verifier. Prior to 0.2.5, the Halo 2 aggregation circuit can mishandle proof points encoded as the point at infinity. `EcPointLoader::multi_scalar_multiplication` places a `Value::Assigned(_)` base paired with `Value::Constant(ONE)` into its unscaled variable-base list and passes it directly to `sum_with_const`. The default shim delegates to halo2-lib `EccChip::sum`, whose incomplete affine addition assumes nonidentity input points. A prover-controlled proof point encoded as `(0, 0)` can therefore enter the final aggregation sum through the scalar-one shortcut and affect the MSM or accumulator computation. Practical exploitability depends on the surrounding aggregation and final-decider checks; the advisory does not establish universal acceptance of invalid proofs. This issue is fixed in version 0.2.5.

- [https://github.com/googlesky/CVE-2026-62337](https://github.com/googlesky/CVE-2026-62337) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-62337.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-62337.svg)


## CVE-2026-61513
 VeraCrypt through 1.26.31 on Linux contains an improper path restriction vulnerability in the elevated CoreService, which passes the path and owner UID from a SetFileOwnerRequest directly to chown() in CoreUnix::SetFileOwner without target validation on Linux. An attacker with an active elevated CoreService session and same-UID access who reopens the request pipe through /proc/pid/fd/n can take ownership of arbitrary system files such as /etc/passwd and /etc/shadow, achieving full root compromise.

- [https://github.com/Haitam-lazaar/veracrypt-setfileowner-lpe](https://github.com/Haitam-lazaar/veracrypt-setfileowner-lpe) :  ![starts](https://img.shields.io/github/stars/Haitam-lazaar/veracrypt-setfileowner-lpe.svg) ![forks](https://img.shields.io/github/forks/Haitam-lazaar/veracrypt-setfileowner-lpe.svg)


## CVE-2026-61512
 VeraCrypt before 1.26.30 on Linux contains a command injection vulnerability in CoreUnix::CheckFilesystem that allows a local attacker with same-UID access and an active elevated CoreService session to execute arbitrary commands by injecting an unsanitized VirtualDevice value into a shell command string. Attackers can reopen the request pipe through /proc/pid/fd/n and supply a crafted VirtualDevice value such as /dev/null; command to achieve arbitrary command execution as root.

- [https://github.com/Haitam-lazaar/veracrypt-checkfs-lpe](https://github.com/Haitam-lazaar/veracrypt-checkfs-lpe) :  ![starts](https://img.shields.io/github/stars/Haitam-lazaar/veracrypt-checkfs-lpe.svg) ![forks](https://img.shields.io/github/forks/Haitam-lazaar/veracrypt-checkfs-lpe.svg)


## CVE-2026-59831
 GitHub CLI (gh) is GitHub’s official command line tool. From 2.10.0 through 2.95.0, connecting to a malicious Codespace with gh codespace jupyter can allow command execution because the command opens a JupyterLab URL supplied by a process inside the Codespace without validating that it is a loopback HTTP or HTTPS address, allowing a crafted vscode:// or vscode-insiders:// URL to be handed to VS Code. This issue is fixed in version 2.96.0.

- [https://github.com/googlesky/CVE-2026-59831](https://github.com/googlesky/CVE-2026-59831) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-59831.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-59831.svg)


## CVE-2026-59415
 Applications that pass externally supplied or user-controlled document IDs to VectorStore.delete(ListString) backed by TypesenseVectorStore are affected.

- [https://github.com/daehyuh/CVE-2026-59415](https://github.com/daehyuh/CVE-2026-59415) :  ![starts](https://img.shields.io/github/stars/daehyuh/CVE-2026-59415.svg) ![forks](https://img.shields.io/github/forks/daehyuh/CVE-2026-59415.svg)


## CVE-2026-59191
 TwigView plugin for CakePHP provides wrappers for common View operations and extensions that expose CakePHP functions and jasny/twig-extensions helpers. Prior to versions 1.3.3 and 2.1.2, if FileLoader::findTemplate() is supplied un-validated user controlled data, arbitrary files can be read. This issue has been patched in versions 1.3.3 and 2.1.2.

- [https://github.com/googlesky/CVE-2026-59191](https://github.com/googlesky/CVE-2026-59191) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-59191.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-59191.svg)


## CVE-2026-58262
 Klever-Go is the Go implementation of the Klever blockchain protocol. Prior to 1.7.20, header signature verification counts the unused padding bits of the PubKeysBitmap toward the two-thirds validator quorum. These padding bits do not correspond to any validator and are ignored by the actual BLS aggregate-signature check, so a malicious or compromised block producer can set them to reach the required quorum while gathering fewer genuine validator signatures than the protocol demands. As a result, nodes that import or intercept the header accept it as correctly signed without a real two-thirds quorum, weakening consensus safety and undermining finality. This issue is fixed in version 1.7.20.

- [https://github.com/googlesky/CVE-2026-58262](https://github.com/googlesky/CVE-2026-58262) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-58262.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-58262.svg)


## CVE-2026-50691
 Improper authorization in M365 Copilot allows an authorized attacker to elevate privileges over a network.

- [https://github.com/cveForge/CVE-2026-50691](https://github.com/cveForge/CVE-2026-50691) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-50691.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-50691.svg)


## CVE-2026-49965
 DreameHome cloud API before 2026-11-19 contained an insecure direct object reference vulnerability in the POST /smart-app/meari-cloud/bindDevice endpoint that allows authenticated attackers to reassign another user's camera to their own Dreame account. The endpoint accepted binding requests from accounts that did not own the camera, so an attacker with the camera identifiers could supply their own user identity, become the camera's masterUid, and remove the camera from the owner's device list, denying the owner access through DreameHome.

- [https://github.com/cveForge/CVE-2026-49965](https://github.com/cveForge/CVE-2026-49965) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-49965.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-49965.svg)


## CVE-2026-48751
 Incus is a system container and virtual machine manager. Prior to version 7.2.0, instance snapshots ignore the `restricted.containers.lowlevel=block` setting; allowing for arbitrary command execution on the Incus server by abusing lowlevel hooks such as `raw.lxc` and `raw.qemu`. Version 7.2.0 patches the issue.

- [https://github.com/googlesky/CVE-2026-48751](https://github.com/googlesky/CVE-2026-48751) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-48751.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-48751.svg)


## CVE-2026-45247
 Mirasvit Full Page Cache Warmer for Magento 2 before version 1.11.12 contains a PHP object injection vulnerability that allows unauthenticated attackers to achieve remote code execution by supplying a crafted serialized PHP object in the CacheWarmer cookie. Attackers can exploit the unrestricted call to PHP's native unserialize() function combined with gadget chains available in Magento and its dependencies to execute arbitrary code on the server.

- [https://github.com/cveForge/CVE-2026-45247](https://github.com/cveForge/CVE-2026-45247) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-45247.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-45247.svg)


## CVE-2026-35376
 A Time-of-Check to Time-of-Use (TOCTOU) vulnerability exists in the chcon utility of uutils coreutils during recursive operations. The implementation resolves recursive targets using a fresh path lookup (via fts_accpath) rather than binding the traversal and label application to the specific directory state encountered during traversal. Because these operations are not anchored to file descriptors, a local attacker with write access to a directory tree can exploit timing-sensitive rename or symbolic link races to redirect a privileged recursive relabeling operation to unintended files or directories. This vulnerability breaks the hardening expectations for SELinux administration workflows and can lead to the unauthorized modification of security labels on sensitive system objects.

- [https://github.com/googlesky/CVE-2026-35376](https://github.com/googlesky/CVE-2026-35376) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-35376.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-35376.svg)


## CVE-2026-33704
 Chamilo LMS is a learning management system. Prior to 1.11.38, any authenticated user (including students) can write arbitrary content to files on the server via the BigUpload endpoint. The key parameter controls the filename and the raw POST body becomes the file content. While .php extensions are filtered to .phps, the .pht extension passes through unmodified. On Apache configurations where .pht is handled as PHP, this leads to Remote Code Execution. This vulnerability is fixed in 1.11.38.

- [https://github.com/duypt02/CVE-2026-33704-PoC](https://github.com/duypt02/CVE-2026-33704-PoC) :  ![starts](https://img.shields.io/github/stars/duypt02/CVE-2026-33704-PoC.svg) ![forks](https://img.shields.io/github/forks/duypt02/CVE-2026-33704-PoC.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/JnamerZ/CopyFail-CVE-2026-31431](https://github.com/JnamerZ/CopyFail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/JnamerZ/CopyFail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/JnamerZ/CopyFail-CVE-2026-31431.svg)


## CVE-2026-30940
 baserCMS is a website development framework. Prior to version 5.2.3, a path traversal vulnerability exists in the theme file management API (/baser/api/admin/bc-theme-file/theme_files/add.json) that allows arbitrary file write. An authenticated administrator can include ../ sequences in the path parameter to create a PHP file in an arbitrary directory outside the theme directory, which may result in remote code execution (RCE). This issue has been patched in version 5.2.3.

- [https://github.com/googlesky/CVE-2026-30940](https://github.com/googlesky/CVE-2026-30940) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-30940.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-30940.svg)


## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.

- [https://github.com/0o176/CVE-2026-29000_PoC](https://github.com/0o176/CVE-2026-29000_PoC) :  ![starts](https://img.shields.io/github/stars/0o176/CVE-2026-29000_PoC.svg) ![forks](https://img.shields.io/github/forks/0o176/CVE-2026-29000_PoC.svg)


## CVE-2026-22816
 Gradle is a build automation tool, and its native-platform tool provides Java bindings for native APIs. When resolving dependencies in versions before 9.3.0, some exceptions were not treated as fatal errors and would not cause a repository to be disabled. If a build encountered one of these exceptions, Gradle would continue to the next repository in the list and potentially resolve dependencies from a different repository. If a Gradle build used an unresolvable host name, Gradle would continue to work as long as all dependencies could be resolved from another repository. An unresolvable host name could be caused by allowing a repository's domain name registration to lapse or typo-ing the real domain name. This behavior could allow an attacker to register a service under the host name used by the build and serve malicious artifacts. The attack requires the repository to be listed before others in the build configuration. Gradle has introduced a change in behavior in Gradle 9.3.0 to stop searching other repositories when encountering these errors.

- [https://github.com/googlesky/CVE-2026-22816](https://github.com/googlesky/CVE-2026-22816) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-22816.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-22816.svg)


## CVE-2026-22679
 Weaver (Fanwei) E-cology 10.0 versions prior to 20260312 contain an unauthenticated remote code execution vulnerability in the /papi/esearch/data/devops/dubboApi/debug/method endpoint that allows attackers to execute arbitrary commands by invoking exposed debug functionality. Attackers can craft POST requests with attacker-controlled interfaceName and methodName parameters to reach command-execution helpers and achieve arbitrary command execution on the system. Exploitation evidence was first observed by the Shadowserver Foundation on 2026-03-31 (UTC).

- [https://github.com/cveForge/CVE-2026-22679](https://github.com/cveForge/CVE-2026-22679) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-22679.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-22679.svg)


## CVE-2026-19868
 An authentication enforcement vulnerability in SonicOS SSLVPN service may allow a user with valid credentials for an alternate authentication method to bypass SAML authentication controls. Successful exploitation may also bypass SAML-enforced multi-factor authentication (MFA).

- [https://github.com/cveForge/CVE-2026-19868](https://github.com/cveForge/CVE-2026-19868) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-19868.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-19868.svg)


## CVE-2026-14492
 The WP Duplicate – WordPress Migration Plugin plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 1.1.11 via the save_single_batch_file function. This is due to a PHP type-juggling authentication bypass via loose != comparison with no is_string() guard, combined with unsanitized base64-decoded path construction in save_single_batch_file() lacking any directory traversal containment. This makes it possible for authenticated attackers, with custom-level access and above, to execute code on the server. Exploitation requires that the site owner has completed the plugin's initial setup so that the site_type and prod_key_random_id options are non-empty, though any non-empty secret value is bypassable via the type-juggling flaw.

- [https://github.com/cveForge/CVE-2026-14492](https://github.com/cveForge/CVE-2026-14492) :  ![starts](https://img.shields.io/github/stars/cveForge/CVE-2026-14492.svg) ![forks](https://img.shields.io/github/forks/cveForge/CVE-2026-14492.svg)


## CVE-2026-12390
 In AzeoTech DAQFactory versions 21.1 and prior, a Type Confusion vulnerability can be exploited by an attacker using specially crafted .ctl files which can result in code execution.

- [https://github.com/dinosn/CVE-2026-123903](https://github.com/dinosn/CVE-2026-123903) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-123903.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-123903.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Ethen1212/php2shell-CVE-2026-109618](https://github.com/Ethen1212/php2shell-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/Ethen1212/php2shell-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/Ethen1212/php2shell-CVE-2026-109618.svg)
- [https://github.com/debugactiveprocess/CVE-2026-109618](https://github.com/debugactiveprocess/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/CVE-2026-109618.svg)
- [https://github.com/skydwn/CVE-2026-109618](https://github.com/skydwn/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/skydwn/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/skydwn/CVE-2026-109618.svg)


## CVE-2026-9999
 Inappropriate implementation in ANGLE in Google Chrome on Mac prior to 148.0.7778.216 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Hazem-A-Fouda/CVE-2026-9999-PoC](https://github.com/Hazem-A-Fouda/CVE-2026-9999-PoC) :  ![starts](https://img.shields.io/github/stars/Hazem-A-Fouda/CVE-2026-9999-PoC.svg) ![forks](https://img.shields.io/github/forks/Hazem-A-Fouda/CVE-2026-9999-PoC.svg)


## CVE-2026-4349
 A vulnerability was determined in Duende IdentityServer4 up to 4.1.2. The affected element is an unknown function of the file /connect/authorize of the component Token Renewal Endpoint. This manipulation of the argument id_token_hint causes improper authentication. It is possible to initiate the attack remotely. The attack is considered to have high complexity. The exploitability is described as difficult. This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/color88/CVE-2022-22706-CVE-2026-43499-y70t](https://github.com/color88/CVE-2022-22706-CVE-2026-43499-y70t) :  ![starts](https://img.shields.io/github/stars/color88/CVE-2022-22706-CVE-2026-43499-y70t.svg) ![forks](https://img.shields.io/github/forks/color88/CVE-2022-22706-CVE-2026-43499-y70t.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/erlangparasu/mitigate_cve_2026_31431-sh](https://github.com/erlangparasu/mitigate_cve_2026_31431-sh) :  ![starts](https://img.shields.io/github/stars/erlangparasu/mitigate_cve_2026_31431-sh.svg) ![forks](https://img.shields.io/github/forks/erlangparasu/mitigate_cve_2026_31431-sh.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-pnpm.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-bun.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-monorepo-nextjs-npm-nested-versions.svg)


## CVE-2025-64669
 Improper access control in Windows Admin Center allows an authorized attacker to elevate privileges locally.

- [https://github.com/nschulz883/wac-threat-detection-CVE-2025-64669](https://github.com/nschulz883/wac-threat-detection-CVE-2025-64669) :  ![starts](https://img.shields.io/github/stars/nschulz883/wac-threat-detection-CVE-2025-64669.svg) ![forks](https://img.shields.io/github/forks/nschulz883/wac-threat-detection-CVE-2025-64669.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/punitdarji/roundcube-cve-2025-49113](https://github.com/punitdarji/roundcube-cve-2025-49113) :  ![starts](https://img.shields.io/github/stars/punitdarji/roundcube-cve-2025-49113.svg) ![forks](https://img.shields.io/github/forks/punitdarji/roundcube-cve-2025-49113.svg)


## CVE-2025-30066
 tj-actions changed-files before 46 allows remote attackers to discover secrets by reading actions logs. (The tags v1 through v45.0.7 were affected on 2025-03-14 and 2025-03-15 because they were modified by a threat actor to point at commit 0e58ed8, which contained malicious updateFeatures code.)

- [https://github.com/Seif-Abdelhamid/actions-compromise-scoper](https://github.com/Seif-Abdelhamid/actions-compromise-scoper) :  ![starts](https://img.shields.io/github/stars/Seif-Abdelhamid/actions-compromise-scoper.svg) ![forks](https://img.shields.io/github/forks/Seif-Abdelhamid/actions-compromise-scoper.svg)


## CVE-2025-26644
 Automated recognition mechanism with inadequate detection or handling of adversarial input perturbations in Windows Hello allows an unauthorized attacker to perform spoofing locally.

- [https://github.com/enese94/windows-hello-ir-only](https://github.com/enese94/windows-hello-ir-only) :  ![starts](https://img.shields.io/github/stars/enese94/windows-hello-ir-only.svg) ![forks](https://img.shields.io/github/forks/enese94/windows-hello-ir-only.svg)


## CVE-2025-21479
 Memory corruption due to unauthorized command execution in GPU micronode while executing specific sequence of commands.

- [https://github.com/Type010/cheese-app](https://github.com/Type010/cheese-app) :  ![starts](https://img.shields.io/github/stars/Type010/cheese-app.svg) ![forks](https://img.shields.io/github/forks/Type010/cheese-app.svg)


## CVE-2025-6647
The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a write past the end of an allocated object. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-26644.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-alias.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-tilde.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2024-53677
You can find more details in  https://cwiki.apache.org/confluence/display/WW/S2-067

- [https://github.com/punitdarji/Apache-struts-cve-2024-53677](https://github.com/punitdarji/Apache-struts-cve-2024-53677) :  ![starts](https://img.shields.io/github/stars/punitdarji/Apache-struts-cve-2024-53677.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Apache-struts-cve-2024-53677.svg)


## CVE-2024-37606
 A Stack overflow vulnerability in D-Link DCS-932L REVB_FIRMWARE_2.18.01 allows attackers to cause a Denial of Service (DoS) via a crafted HTTP request.

- [https://github.com/itwizardo/DCS932L-Emulation-CVE-2024-37606-Attack](https://github.com/itwizardo/DCS932L-Emulation-CVE-2024-37606-Attack) :  ![starts](https://img.shields.io/github/stars/itwizardo/DCS932L-Emulation-CVE-2024-37606-Attack.svg) ![forks](https://img.shields.io/github/forks/itwizardo/DCS932L-Emulation-CVE-2024-37606-Attack.svg)


## CVE-2024-36401
Versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2 contain a patch for the issue. A workaround exists by removing the `gt-complex-x.y.jar` file from the GeoServer where `x.y` is the GeoTools version (e.g., `gt-complex-31.1.jar` if running GeoServer 2.25.1). This will remove the vulnerable code from GeoServer but may break some GeoServer functionality or prevent GeoServer from deploying if the gt-complex module is needed.

- [https://github.com/punitdarji/GeoServer-CVE-2024-36401](https://github.com/punitdarji/GeoServer-CVE-2024-36401) :  ![starts](https://img.shields.io/github/stars/punitdarji/GeoServer-CVE-2024-36401.svg) ![forks](https://img.shields.io/github/forks/punitdarji/GeoServer-CVE-2024-36401.svg)


## CVE-2024-29269
 An issue discovered in Telesquare TLR-2005Ksh 1.0.0 and 1.1.4 allows attackers to run arbitrary system commands via the Cmd parameter.

- [https://github.com/K3ysTr0K3R/CVE-2024-29269-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-29269-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2024-29269-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2024-29269-EXPLOIT.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/K3ysTr0K3R/CVE-2024-27198-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-27198-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2024-27198-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2024-27198-EXPLOIT.svg)


## CVE-2024-25600
 Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

- [https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2024-25600-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2024-25600-EXPLOIT.svg)


## CVE-2024-10914
 A vulnerability was found in D-Link DNS-320, DNS-320LW, DNS-325 and DNS-340L up to 20241028. It has been declared as critical. Affected by this vulnerability is the function cgi_user_add of the file /cgi-bin/account_mgr.cgi?cmd=cgi_user_add. The manipulation of the argument name leads to os command injection. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used.

- [https://github.com/K3ysTr0K3R/CVE-2024-10914-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-10914-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2024-10914-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2024-10914-EXPLOIT.svg)


## CVE-2024-9264
 The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distributions.

- [https://github.com/punitdarji/Grafana-CVE-2024-9264](https://github.com/punitdarji/Grafana-CVE-2024-9264) :  ![starts](https://img.shields.io/github/stars/punitdarji/Grafana-CVE-2024-9264.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Grafana-CVE-2024-9264.svg)


## CVE-2024-4577
 In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

- [https://github.com/K3ysTr0K3R/CVE-2024-4577-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-4577-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2024-4577-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2024-4577-EXPLOIT.svg)


## CVE-2024-3273
 ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability, which was classified as critical, was found in D-Link DNS-320L, DNS-325, DNS-327L and DNS-340L up to 20240403. Affected is an unknown function of the file /cgi-bin/nas_sharing.cgi of the component HTTP GET Request Handler. The manipulation of the argument system leads to command injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-259284. NOTE: This vulnerability only affects products that are no longer supported by the maintainer. NOTE: Vendor was contacted early and confirmed immediately that the product is end-of-life. It should be retired and replaced.

- [https://github.com/K3ysTr0K3R/CVE-2024-3273-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2024-3273-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2024-3273-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2024-3273-EXPLOIT.svg)


## CVE-2024-1561
 An issue was discovered in gradio-app/gradio, where the `/component_server` endpoint improperly allows the invocation of any method on a `Component` class with attacker-controlled arguments. Specifically, by exploiting the `move_resource_to_block_cache()` method of the `Block` class, an attacker can copy any file on the filesystem to a temporary directory and subsequently retrieve it. This vulnerability enables unauthorized local file read access, posing a significant risk especially when the application is exposed to the internet via `launch(share=True)`, thereby allowing remote attackers to read files on the host machine. Furthermore, gradio apps hosted on `huggingface.co` are also affected, potentially leading to the exposure of sensitive information such as API keys and credentials stored in environment variables.

- [https://github.com/K3ysTr0K3R/CVE-2024-1561](https://github.com/K3ysTr0K3R/CVE-2024-1561) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2024-1561.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2024-1561.svg)


## CVE-2024-0012
Cloud NGFW and Prisma Access are not impacted by this vulnerability.

- [https://github.com/punitdarji/Paloalto-CVE-2024-0012](https://github.com/punitdarji/Paloalto-CVE-2024-0012) :  ![starts](https://img.shields.io/github/stars/punitdarji/Paloalto-CVE-2024-0012.svg) ![forks](https://img.shields.io/github/forks/punitdarji/Paloalto-CVE-2024-0012.svg)


## CVE-2023-51467
 The vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code

- [https://github.com/K3ysTr0K3R/CVE-2023-51467-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2023-51467-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2023-51467-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2023-51467-EXPLOIT.svg)


## CVE-2023-50465
 A stored cross-site scripting (XSS) vulnerability exists in Monica (aka MonicaHQ) 4.0.0 via an SVG document uploaded by an authenticated user.

- [https://github.com/javaxcf/CVE-2023-50465](https://github.com/javaxcf/CVE-2023-50465) :  ![starts](https://img.shields.io/github/stars/javaxcf/CVE-2023-50465.svg) ![forks](https://img.shields.io/github/forks/javaxcf/CVE-2023-50465.svg)


## CVE-2023-43208
 NextGen Healthcare Mirth Connect before version 4.4.1 is vulnerable to unauthenticated remote code execution. Note that this vulnerability is caused by the incomplete patch of CVE-2023-37679.

- [https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2023-43208-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2023-43208-EXPLOIT.svg)


## CVE-2023-32315
 Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to upgrade. If an Openfire upgrade isn’t available for a specific release, or isn’t quickly actionable, users may see the linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.

- [https://github.com/K3ysTr0K3R/CVE-2023-32315-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2023-32315-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2023-32315-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2023-32315-EXPLOIT.svg)


## CVE-2023-26083
 Memory leak vulnerability in Mali GPU Kernel Driver in Midgard GPU Kernel Driver all versions from r6p0 - r32p0, Bifrost GPU Kernel Driver all versions from r0p0 - r42p0, Valhall GPU Kernel Driver all versions from r19p0 - r42p0, and Avalon GPU Kernel Driver all versions from r41p0 - r42p0 allows a non-privileged user to make valid GPU processing operations that expose sensitive kernel metadata.

- [https://github.com/color88/CVE-2022-22706-CVE-2026-43499-y70t](https://github.com/color88/CVE-2022-22706-CVE-2026-43499-y70t) :  ![starts](https://img.shields.io/github/stars/color88/CVE-2022-22706-CVE-2026-43499-y70t.svg) ![forks](https://img.shields.io/github/forks/color88/CVE-2022-22706-CVE-2026-43499-y70t.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2023-23752-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2023-23752-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2023-23752-EXPLOIT.svg)


## CVE-2022-34753
 A CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability exists that could cause remote root exploit when the command is compromised. Affected Products: SpaceLogic C-Bus Home Controller (5200WHC2), formerly known as C-Bus Wiser Homer Controller MK2 (V1.31.460 and prior)

- [https://github.com/K3ysTr0K3R/CVE-2022-34753-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2022-34753-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2022-34753-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2022-34753-EXPLOIT.svg)


## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/K3ysTr0K3R/CVE-2022-33891-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2022-33891-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2022-33891-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2022-33891-EXPLOIT.svg)


## CVE-2022-22706
 Arm Mali GPU Kernel Driver allows a non-privileged user to achieve write access to read-only memory pages. This affects Midgard r26p0 through r31p0, Bifrost r0p0 through r35p0, and Valhall r19p0 through r35p0.

- [https://github.com/color88/CVE-2022-22706-CVE-2026-43499-y70t](https://github.com/color88/CVE-2022-22706-CVE-2026-43499-y70t) :  ![starts](https://img.shields.io/github/stars/color88/CVE-2022-22706-CVE-2026-43499-y70t.svg) ![forks](https://img.shields.io/github/forks/color88/CVE-2022-22706-CVE-2026-43499-y70t.svg)


## CVE-2022-0739
 The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

- [https://github.com/DAEMON-404/HTB-Lab-Writeups](https://github.com/DAEMON-404/HTB-Lab-Writeups) :  ![starts](https://img.shields.io/github/stars/DAEMON-404/HTB-Lab-Writeups.svg) ![forks](https://img.shields.io/github/forks/DAEMON-404/HTB-Lab-Writeups.svg)


## CVE-2022-0543
 It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

- [https://github.com/K3ysTr0K3R/CVE-2022-0543](https://github.com/K3ysTr0K3R/CVE-2022-0543) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2022-0543.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2022-0543.svg)


## CVE-2022-0165
 The Page Builder KingComposer WordPress plugin through 2.9.6 does not validate the id parameter before redirecting the user to it via the kc_get_thumbn AJAX action available to both unauthenticated and authenticated users

- [https://github.com/K3ysTr0K3R/CVE-2022-0165-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2022-0165-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2022-0165-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2022-0165-EXPLOIT.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `grafana_host_url/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/K3ysTr0K3R/CVE-2021-43798-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-43798-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-43798-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-43798-EXPLOIT.svg)


## CVE-2021-43789
 PrestaShop is an Open Source e-commerce web application. Versions of PrestaShop prior to 1.7.8.2 are vulnerable to blind SQL injection using search filters with `orderBy` and `sortOrder` parameters. The problem is fixed in version 1.7.8.2.

- [https://github.com/K3ysTr0K3R/CVE-2021-43798-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-43798-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-43798-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-43798-EXPLOIT.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/K3ysTr0K3R/CVE-2021-42013-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-42013-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-42013-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-42013-EXPLOIT.svg)


## CVE-2021-34621
 A vulnerability in the user registration component found in the ~/src/Classes/RegistrationAuth.php file of the ProfilePress WordPress plugin made it possible for users to register on sites as an administrator. This issue affects versions 3.0.0 - 3.1.3. .

- [https://github.com/K3ysTr0K3R/CVE-2021-34621-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-34621-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-34621-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-34621-EXPLOIT.svg)


## CVE-2021-29447
 Wordpress is an open source CMS. A user with the ability to upload files (like an Author) can exploit an XML parsing issue in the Media Library leading to XXE attacks. This requires WordPress installation to be using PHP 8. Access to internal files is possible in a successful XXE attack. This has been patched in WordPress version 5.7.1, along with the older affected versions via a minor release. We strongly recommend you keep auto-updates enabled.

- [https://github.com/DAEMON-404/HTB-Lab-Writeups](https://github.com/DAEMON-404/HTB-Lab-Writeups) :  ![starts](https://img.shields.io/github/stars/DAEMON-404/HTB-Lab-Writeups.svg) ![forks](https://img.shields.io/github/forks/DAEMON-404/HTB-Lab-Writeups.svg)


## CVE-2021-29441
 Nacos is a platform designed for dynamic service discovery and configuration and service management. In Nacos before version 1.4.1, when configured to use authentication (-Dnacos.core.auth.enabled=true) Nacos uses the AuthFilter servlet filter to enforce authentication. This filter has a backdoor that enables Nacos servers to bypass this filter and therefore skip authentication checks. This mechanism relies on the user-agent HTTP header so it can be easily spoofed. This issue may allow any user to carry out any administrative tasks on the Nacos server.

- [https://github.com/K3ysTr0K3R/CVE-2021-29441](https://github.com/K3ysTr0K3R/CVE-2021-29441) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-29441.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-29441.svg)


## CVE-2021-22873
 Revive Adserver before 5.1.0 is vulnerable to open redirects via the `dest`, `oadest`, and/or `ct0` parameters of the lg.php and ck.php delivery scripts. Such open redirects had previously been available by design to allow third party ad servers to track such metrics when delivering ads. However, third party click tracking via redirects is not a viable option anymore, leading to such open redirect functionality being removed and reclassified as a vulnerability.

- [https://github.com/K3ysTr0K3R/CVE-2021-22873-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-22873-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-22873-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-22873-EXPLOIT.svg)


## CVE-2021-22205
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

- [https://github.com/K3ysTr0K3R/CVE-2021-22205](https://github.com/K3ysTr0K3R/CVE-2021-22205) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-22205.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-22205.svg)


## CVE-2021-4191
 An issue has been discovered in GitLab CE/EE affecting versions 13.0 to 14.6.5, 14.7 to 14.7.4, and 14.8 to 14.8.2. Private GitLab instances with restricted sign-ups may be vulnerable to user enumeration to unauthenticated users through the GraphQL API.

- [https://github.com/K3ysTr0K3R/CVE-2021-4191-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2021-4191-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2021-4191-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2021-4191-EXPLOIT.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/tr3m0x/CVE-2021-41773](https://github.com/tr3m0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/tr3m0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/tr3m0x/CVE-2021-41773.svg)
- [https://github.com/sixpacksecurity/CVE-2021-41773](https://github.com/sixpacksecurity/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sixpacksecurity/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sixpacksecurity/CVE-2021-41773.svg)
- [https://github.com/xMohamed0/CVE-2021-41773](https://github.com/xMohamed0/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/xMohamed0/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/xMohamed0/CVE-2021-41773.svg)


## CVE-2020-13945
 In Apache APISIX, the user enabled the Admin API and deleted the Admin API access IP restriction rules. Eventually, the default token is allowed to access APISIX management data. This affects versions 1.2, 1.3, 1.4, 1.5.

- [https://github.com/K3ysTr0K3R/CVE-2020-13945-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2020-13945-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2020-13945-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2020-13945-EXPLOIT.svg)


## CVE-2020-1971
 The X.509 GeneralName type is a generic type for representing different types of names. One of those name types is known as EDIPartyName. OpenSSL provides a function GENERAL_NAME_cmp which compares different instances of a GENERAL_NAME to see if they are equal or not. This function behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME. A NULL pointer dereference and a crash may occur leading to a possible denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function for two purposes: 1) Comparing CRL distribution point names between an available CRL and a CRL distribution point embedded in an X509 certificate 2) When verifying that a timestamp response token signer matches the timestamp authority name (exposed via the API functions TS_RESP_verify_response and TS_RESP_verify_token) If an attacker can control both items being compared then that attacker could trigger a crash. For example if the attacker can trick a client or server into checking a malicious certificate against a malicious CRL then this may occur. Note that some applications automatically download CRLs based on a URL embedded in a certificate. This checking happens prior to the signatures on the certificate and CRL being verified. OpenSSL's s_server, s_client and verify tools have support for the "-crl_download" option which implements automatic CRL downloading and this attack has been demonstrated to work against those tools. Note that an unrelated bug means that affected versions of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME. However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's parser will accept and hence trigger this attack. All OpenSSL 1.1.1 and 1.0.2 versions are affected by this issue. Other OpenSSL releases are out of support and have not been checked. Fixed in OpenSSL 1.1.1i (Affected 1.1.1-1.1.1h). Fixed in OpenSSL 1.0.2x (Affected 1.0.2-1.0.2w).

- [https://github.com/honeyvig/CVE-2020-1971](https://github.com/honeyvig/CVE-2020-1971) :  ![starts](https://img.shields.io/github/stars/honeyvig/CVE-2020-1971.svg) ![forks](https://img.shields.io/github/forks/honeyvig/CVE-2020-1971.svg)


## CVE-2019-17382
 An issue was discovered in zabbix.php?action=dashboard.view&dashboardid=1 in Zabbix through 4.4. An attacker can bypass the login page and access the dashboard page, and then create a Dashboard, Report, Screen, or Map without any Username/Password (i.e., anonymously). All created elements (Dashboard/Report/Screen/Map) are accessible by other users and by an admin.

- [https://github.com/K3ysTr0K3R/CVE-2019-17382-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2019-17382-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2019-17382-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2019-17382-EXPLOIT.svg)


## CVE-2019-15107
 An issue was discovered in Webmin =1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/K3ysTr0K3R/CVE-2019-15107-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2019-15107-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2019-15107-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2019-15107-EXPLOIT.svg)


## CVE-2018-25114
 A remote code execution vulnerability exists within osCommerce Online Merchant version 2.3.4.1 due to insecure default configuration and missing authentication in the installer workflow. By default, the /install/ directory remains accessible after installation. An unauthenticated attacker can invoke install_4.php, submit crafted POST data, and inject arbitrary PHP code into the configure.php file. When the application later includes this file, the injected payload is executed, resulting in full server-side compromise.

- [https://github.com/s4m98/oscommerce_2.3.4_rce](https://github.com/s4m98/oscommerce_2.3.4_rce) :  ![starts](https://img.shields.io/github/stars/s4m98/oscommerce_2.3.4_rce.svg) ![forks](https://img.shields.io/github/forks/s4m98/oscommerce_2.3.4_rce.svg)


## CVE-2018-18778
 ACME mini_httpd before 1.30 lets remote users read arbitrary files.

- [https://github.com/K3ysTr0K3R/CVE-2018-18778](https://github.com/K3ysTr0K3R/CVE-2018-18778) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2018-18778.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2018-18778.svg)


## CVE-2018-14847
 MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files and remote authenticated attackers to write arbitrary files due to a directory traversal vulnerability in the WinBox interface.

- [https://github.com/K3ysTr0K3R/CVE-2018-14847-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2018-14847-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2018-14847-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2018-14847-EXPLOIT.svg)


## CVE-2018-10933
 A vulnerability was found in libssh's server-side state machine before versions 0.7.6 and 0.8.4. A malicious client could create channels without first performing authentication, resulting in unauthorized access.

- [https://github.com/K3ysTr0K3R/CVE-2018-10933](https://github.com/K3ysTr0K3R/CVE-2018-10933) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2018-10933.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2018-10933.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a "Cookie: uid=admin" header, as demonstrated by a device.rsp?opt=user&cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/K3ysTr0K3R/CVE-2018-9995-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2018-9995-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2018-9995-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2018-9995-EXPLOIT.svg)


## CVE-2017-12615
 When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request. This JSP could then be requested and any code it contained would be executed by the server.

- [https://github.com/K3ysTr0K3R/CVE-2017-12615](https://github.com/K3ysTr0K3R/CVE-2017-12615) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-12615.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-12615.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/K3ysTr0K3R/CVE-2017-9841-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-9841-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-9841-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-9841-EXPLOIT.svg)


## CVE-2017-8225
 On Wireless IP Camera (P2P) WIFICAM devices, access to .ini files (containing credentials) is not correctly checked. An attacker can bypass authentication by providing an empty loginuse parameter and an empty loginpas parameter in the URI.

- [https://github.com/K3ysTr0K3R/CVE-2017-8225-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-8225-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-8225-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-8225-EXPLOIT.svg)


## CVE-2017-7921
 An Improper Authentication issue was discovered in Hikvision DS-2CD2xx2F-I Series V5.2.0 build 140721 to V5.4.0 build 160530, DS-2CD2xx0F-I Series V5.2.0 build 140721 to V5.4.0 Build 160401, DS-2CD2xx2FWD Series V5.3.1 build 150410 to V5.4.4 Build 161125, DS-2CD4x2xFWD Series V5.2.0 build 140721 to V5.4.0 Build 160414, DS-2CD4xx5 Series V5.2.0 build 140721 to V5.4.0 Build 160421, DS-2DFx Series V5.2.0 build 140805 to V5.4.5 Build 160928, and DS-2CD63xx Series V5.0.9 build 140305 to V5.3.5 Build 160106 devices. The improper authentication vulnerability occurs when an application does not adequately or correctly authenticate users. This may allow a malicious user to escalate his or her privileges on the system and gain access to sensitive information.

- [https://github.com/K3ysTr0K3R/CVE-2017-7921-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-7921-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-7921-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-7921-EXPLOIT.svg)


## CVE-2017-5487
 wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.

- [https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-5487-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-5487-EXPLOIT.svg)


## CVE-2017-0564
 An elevation of privilege vulnerability in the kernel ION subsystem could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Critical due to the possibility of a local permanent device compromise, which may require reflashing the operating system to repair the device. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID: A-34276203.

- [https://github.com/outmains/CVE-2017-0564-ION-PoC](https://github.com/outmains/CVE-2017-0564-ION-PoC) :  ![starts](https://img.shields.io/github/stars/outmains/CVE-2017-0564-ION-PoC.svg) ![forks](https://img.shields.io/github/forks/outmains/CVE-2017-0564-ION-PoC.svg)


## CVE-2015-10141
 An unauthenticated OS command injection vulnerability exists within Xdebug versions 2.5.5 and earlier, a PHP debugging extension developed by Derick Rethans. When remote debugging is enabled, Xdebug listens on port 9000 and accepts debugger protocol commands without authentication. An attacker can send a crafted eval command over this interface to execute arbitrary PHP code, which may invoke system-level functions such as system() or passthru(). This results in full compromise of the host under the privileges of the web server user.

- [https://github.com/K3ysTr0K3R/CVE-2015-10141](https://github.com/K3ysTr0K3R/CVE-2015-10141) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2015-10141.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2015-10141.svg)


## CVE-2015-2166
 Directory traversal vulnerability in the Instance Monitor in Ericsson Drutt Mobile Service Delivery Platform (MSDP) 4, 5, and 6 allows remote attackers to read arbitrary files via a ..%2f (dot dot encoded slash) in the default URI.

- [https://github.com/K3ysTr0K3R/CVE-2015-2166-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2015-2166-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2015-2166-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2015-2166-EXPLOIT.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/K3ysTr0K3R/CVE-2014-6271-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2014-6271-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2014-6271-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2014-6271-EXPLOIT.svg)


## CVE-2012-2122
 sql/password.c in Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, and 5.6.x before 5.6.6, and MariaDB 5.1.x before 5.1.62, 5.2.x before 5.2.12, 5.3.x before 5.3.6, and 5.5.x before 5.5.23, when running in certain environments with certain implementations of the memcmp function, allows remote attackers to bypass authentication by repeatedly authenticating with the same incorrect password, which eventually causes a token comparison to succeed due to an improperly-checked return value.

- [https://github.com/K3ysTr0K3R/CVE-2012-2122](https://github.com/K3ysTr0K3R/CVE-2012-2122) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2012-2122.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2012-2122.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/K3ysTr0K3R/CVE-2012-1823](https://github.com/K3ysTr0K3R/CVE-2012-1823) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2012-1823.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2012-1823.svg)


## CVE-2010-4231
 Directory traversal vulnerability in the web-based administration interface on the Camtron CMNC-200 Full HD IP Camera and TecVoz CMNC-200 Megapixel IP Camera with firmware 1.102A-008 allows remote attackers to read arbitrary files via a .. (dot dot) in the URI.

- [https://github.com/K3ysTr0K3R/CVE-2010-4231-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2010-4231-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2010-4231-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2010-4231-EXPLOIT.svg)


## CVE-2008-5862
 Directory traversal vulnerability in webcamXP 5.3.2.375 and 5.3.2.410 build 2132 allows remote attackers to read arbitrary files via a ..%2F (encoded dot dot slash) in the URI.

- [https://github.com/K3ysTr0K3R/CVE-2008-5862-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2008-5862-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2008-5862-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2008-5862-EXPLOIT.svg)

