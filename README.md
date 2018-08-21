All credits to fireworm71 et al & effectsToCause et al etc etc.

This Fork is focused on ARMV8/aarch64 sbc's based on Allwinner H5, H6, A64 etc and any board with 64-bit OS that has Cortex-a53 (or above) CPU. This reduces the memory requirements of the default work thread of 3ways (now 2ways) by 1/3rd without performance penalty allowing more of said threads to run on the typically low ram boards currently available. For example, I am able to run "-t 2 --oneways=2" on my 1gb boards. (* See edit below) I initially hoped for 3x 2ways & 1x 1ways with "-t 3 --oneways=1" however the bloated Linux Kernel in my manufacturer (Orange Pi) provided Ubuntu kills it due to lack of free memory...

*EDIT custom Ubuntu images for Orange Pi One Plus & Orange Pi Lite2 available with miner binary preinstalled. Refer to start up guide at https://drive.google.com/open?id=14e1c96l1_FAa9fWFUJNB3MepgYpWrpoV for download links.
Adding "echo 0 | tee /proc/sys/vm/min_free_kbytes" to /etc/rc.local and reconfiguring/rebuilding the kernel to include hugepages (madvise) support (then adding "echo always | tee /sys/kernel/mm/transparent_hugepage/enabled" to rc.local) and removing unneeded features to get the kernel Image file below 8mb in size allows -t 3 --oneways=1 on boards with 1gb ram also with as few services running as possible, e.g. replacing sshd with dropbear and disabling network manager only using /etc/network/interfaces for LAN/Wifi connection profiles.

Use the original fireworm71 miner for other platforms, or effectsToCause miner if you have 32-bit x86.

If you have ubuntu 16.04 get gcc8 and compile using instructions below...If you do not have cortex-a53 (e.g. cortex-a57) replace "-mcpu=cortex-a53" with "-march=armv8-a". In addition to using gcc8 for compile, these instructions include link time optimization.

# Note, I consider this ppa to be a bit broken however I found it is safe as long I do not uninstall gcc8 after.

sudo add-apt-repository -y ppa:jonathonf/gcc

sudo apt-get update

sudo apt-get install gcc-8

sudo apt-get install g++-8

Refer to rest of this Readme for installing other dependancies.

./autogen.sh

./configure CC="gcc-8" CXX="g++-8" CFLAGS="-O3 -mcpu=cortex-a53+crypto -flto -fuse-linker-plugin -funroll-loops" CXXFLAGS="-O3 -mcpu=cortex-a53+crypto -flto -fuse-linker-plugin -funroll-loops" RANLIB="aarch64-linux-gnu-gcc-ranlib-8 --plugin=$(gcc-8 --print-file-name=liblto_plugin.so)" ARFLAGS="cr --plugin=$(gcc-8 --print-file-name=liblto_plugin.so)" --with-curl --with-crypto

make RANLIB="aarch64-linux-gnu-gcc-ranlib-8 --plugin=$(gcc-8 --print-file-name=liblto_plugin.so)" ARFLAGS=" cr --plugin=$(gcc-8 --print-file-name=liblto_plugin.so)" LDFLAGS="-O3 -mcpu=cortex-a53+crypto -flto -fuse-linker-plugin -funroll-loops" AR="aarch64-linux-gnu-gcc-ar-8"

(optional step to reduce binary bloat)

strip cpuminer

So what are the benefits of this fork? I calculated to gain 10% compared to the original on my armv8 boards however hit a snag and had to settle for fewer non-oneway threads though still gain about 4-5% in hashrates. Building a new kernel with trimmed config and removing unnecessary services might allow a 1gb board run "-t 3 --oneways=1". If you have 2gb ram, there might be no benefits from this fork so just use the original fireworm71 miner.

So what was changed? I stripped back the scrypt_core_3way() function to reduce it from three to two lanes of processing to reduce memory requirements by 1/3rd with virtually the same performance. More appropriate for the lesser memory capacity/bandwith and small cpu cache found on armv8/aarch64 SOC's.

Provided fireworm71 is satisfied with the changes in this fork, he might merge it into his respository afterwhich I will likely delete this fork.


veriumMiner
==============

This is a multi-threaded CPU miner for Verium using scrypt²,
fork of [tpruvot](//github.com/tpruvot)'s cpuminer-multi (see AUTHORS for list of contributors).

# [Latest Binaries here](https://github.com/fireworm71/veriumMiner/releases/latest)

#### Table of contents

* [Overview](#overview)
* [Download](#download)
* [Dependencies](#dependencies)
* [Build](#build)
* [Usage instructions](#usage-instructions)
  * [HugePages Linux](#hugepages-linux)
  * [HugePages Windows](#hugepages-windows)
* [Donations](#donations)
* [GCC 7.2](#gcc)
* [Credits](#credits)
* [License](#license)

Overview
========
To use this miner, you can do one of the following:
* Grab a precompiled exe [here](https://github.com/fireworm71/veriumMiner/releases/latest).
* Build from source: Easy:
  ```
  [install dependencies for your os]
  git clone https://github.com/fireworm71/veriumMiner
  cd veriumMiner
  ./build.sh
  ./cpuminer ...
  ```
* Build from source: Advanced:
  ```
  [install dependencies for your os]
  git clone https://github.com/fireworm71/veriumMiner
  cd veriumMiner
  ./autogen.sh
  perl nomacro.pl
  ./configure CFLAGS="-O2" --with-curl --with-crypto
  make clean && make
  ./cpuminer ...
  ```

Download
========
 * Git tree:   https://github.com/fireworm71/veriumMiner
 * Clone with `git clone https://github.com/fireworm71/veriumMiner`
 * [Latest Binaries here](https://github.com/fireworm71/veriumMiner/releases/latest)

Dependencies
============
 * libcurl http://curl.haxx.se/libcurl/
 * jansson http://www.digip.org/jansson/ (jansson source is included in-tree)
 * openssl libcrypto https://www.openssl.org/
 * pthreads
 * zlib (for curl/ssl)

 * Ubuntu / Debian: 
  * `apt-get install automake autoconf pkg-config libcurl4-openssl-dev libjansson-dev libssl-dev libgmp-dev zlib1g-dev`
 * FreeBSD:
  * `pkg install automake autoconf git`
  * Build libcurl by compiling and installing the curl port
    `cd /usr/ports/ftp/curl; make install`

Build
=====

#### Basic *nix build instructions:
 * After dowloading dependencies: `./build.sh`

#### If you are fancy,
 * ./autogen.sh	# only needed if building from git repo
 * ./nomacro.pl	# only needed if building on Mac OS X or with Clang
 * ./configure CFLAGS="-march=native" --with-crypto --with-curl
 * make

#### FreeBSD users:
```
   export C_INCLUDE_PATH=$INCLUDE_PATH:/usr/local/include
   export CPLUS_INCLUDE_PATH=$INCLUDE_PATH:/usr/local/include
   export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
   ./autogen.sh
   /usr/local/bin/perl ./nomacro.pl
   ./configure CFLAGS="-march=native" --with-crypto --with-curl
   make
```

#### Notes for AIX users:
 * To build a 64-bit binary, export OBJECT_MODE=64
 * GNU-style long options are not supported, but are accessible via configuration file

#### Basic Windows build instructions, using MinGW64:
 * Install MSYS 2 64bit
 * Open the MSYS2 64bit Shell

```
Pacman -Syu
```

 * Kill Terminal with taskmanager & reopen

```
pacman -Sy mingw-w64-x86_64-gcc
pacman -Sy make
pacman -Sy automake
pacman -Sy autoconf

pacman -Sy mingw-w64-x86_64-curl
pacman -Sy curl libcurl libcurl-devel mingw-w64-x86_64-curl mingw-w64-x86_64-libwinpthread-git libopenssl openssl openssl-devel
```

 * Download
https://netix.dl.sourceforge.net/project/ezwinports/make-4.2.1-without-guile-w32-bin.zip

 * Copy everything in C:\msys64\mingw64 without replacing anything
 * Download and extract the Miner from Git, place it in C:\msys64
 * Open MSYS2 MinGW64 Shell:
```
cd /veriumMiner-main
./mingw64.sh
```
 * If deploying to another computer, you will also need to copy: `libeay32.dll`, `libjansson-4.dll`, and `libwinpthread-1.dll` from the `C:\msys64\mingw64\bin` folder, as well as `cpuminer.exe`.

#### Architecture-specific notes:
 * ARMv8:
   * Neon is enabled by default, ./build.sh should work fine.
 * ARMv7:
   * No runtime CPU detection. The miner can take advantage of some instructions specific to ARMv5E and later processors, but the decision whether to use them is made at compile time, based on compiler-defined macros.
   * To use NEON instructions, add `-mfpu=neon` to CFLAGS.
 * x86:
   * The miner checks for SSE2 instructions support at runtime, and uses them if they are available.
 * x86-64:	
   * The miner can take advantage of AVX, AVX2 and XOP instructions, but only if both the CPU and the operating system support them.
     * Linux supports AVX starting from kernel version 2.6.30.
     * FreeBSD supports AVX starting with 9.1-RELEASE.
     * Mac OS X added AVX support in the 10.6.8 update.
     * Windows supports AVX starting from Windows 7 SP1 and Windows Server 2008 R2 SP1.
   * The configure script outputs a warning if the assembler doesn't support some instruction sets. In that case, the miner can still be built, but unavailable optimizations are left off.

Usage instructions
==================
Run "cpuminer --help" to see options.

### HugePages 
HugePages allow for faster memory lookups, which is very important for this miner.  Enabling HugePages typically gets 10% or more performance.

#### HugePages (Linux)
To make matters complicated, there are two ways of doing this.  One is `transparent_hugepages` one is `preallocated`.  Even more complicated, one is sometimes faster than the other.

**This miner will use `transparent_hugepages` by default.**

To enable `transparent_hugepages`, (on Ubuntu 16.04):
`echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled`

To disable `transparent_hugepages`, (on Ubuntu 16.04):
`echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled`

To verify the status of `transparent_hugepages`
`cat /sys/kernel/mm/transparent_hugepage/enabled`  (`[]` will show around the current status).

To enable `preallocated` hugepages (on Ubuntu 16.04), first check that you have `/proc/sys/vm/nr_hugepages` by doing `ls /proc/sys/vm` (you should see `nr_hugepages` in the print out).  Then,
1. `sudo nano /etc/sysctl.conf`, 
2. scroll to the bottom, 
3. type in `vm.nr_hugepages=size`
4. `Ctrl+O`, then `[Enter]`, then `Ctrl+X`.
5. `sudo sysctl -p`

To disable:
1. `sudo nano /etc/sysctl.conf`, 
2. scroll to the bottom, 
3. remove the line `vm.nr_hugepages=size`
4. `Ctrl+O`, then `[Enter]`, then `Ctrl+X`.
5. `sudo sysctl -p`

Note that you can also reboot and this will cause HugePages to allocate / deallocate.

When enabling, you should see `vm.nr_hugepages=size` print out on the console.  If not, check your distro.  You may need to recompile your kernel to enable this.  You can also verify that memory is allocated by running `free` and seeing that you now have a ton of memory allocated, but aren't running anything that's using it.

`size` = (the amount of memory each miner thread needs) / (2048 * 1024).  

How much memory is be used per thread?
* 1way : 128MB -> nr_hugepages = 65.
* SSE4 (3way) : 384MB -> nr_hugepages = 193.
* AVX  (3way) : 384MB -> nr_hugepages = 193.
* AVX2 (6way) : 768MB -> nr_hugepages = 386.
* ARMv7 (3way) : 384MB -> nr_hugepages = 193.
* ARMv8 (3way) : 384MB -> nr_hugepages = 193.

Multiply that number by the number of threads, and you will have the size needed.  Note, you may not have enough RAM for this on ARM SoCs.  The miner should still work, but it will not be as optimal. 

For example, 4 threads on an SSE4, you'd type `vm.nr_hugepages=772`.  Since 4 (threads) * 193 (hugepages per thread) = 772.


#### HugePages (Windows)

 * You need to run the miner with "Run As Administrator" on Windows.
 * You need to edit your system's group policies to enable locking large pages. Here are the steps from MSDN: 

 1. On the Start menu, click Run. In the Open box, type gpedit.msc.
 2. On the Local Group Policy Editor console, expand Computer Configuration, and then expand Windows Settings.
 3. Expand Security Settings, and then expand Local Policies.
 4. Select the User Rights Assignment folder.
 5. The policies will be displayed in the details pane.
 6. In the pane, double-click Lock pages in memory.
 7. In the Local Security Setting – Lock pages in memory dialog box, click Add User or Group.
 8. In the Select Users, Service Accounts, or Groups dialog box, add an account that you will run the miner on
 9. Reboot for change to take effect.
  * Windows also tends to fragment memory a lot. If you are running on a system with 4-8GB of RAM you might need to switch off all the auto-start applications and reboot to have a large enough chunk of contiguous memory.

### Oneways, cpu affinity.

You can now specify a number of 'oneway' threads to acompany your 'default way' threads.  Default way is determined by your CPU instruction set.

'-1 n' will specify the number of oneway threads to spawn.  You can also use `--oneways n`.  Some folks (on arm especially) see perf gains due to the implementation.  Additionally, there are new options to help control affinity for these threads and 'default' way threads too.  `--cpu-affinity-stride N`, `--cpu-affinity-default-index N`, `--cpu-affinity-oneway-index N`, and `--cpu-priority-oneway 0-5`

Affinity stride works by saying how many cpus should be skipped before assigning the thread to it.  So, if you have 8 cpu's and set 'stride' to 3, you will start with CPU (0 + 3 * 0), then CPU (0 + 3 * 1), then CPU (0 + 3 * 2),  aka  CPU's 0, 3, 6.  'default' index is the starting index ('0' in the example) for the number of `-t` threads.  'oneway-index' is the starting index for oneway `-1` threads.

Play around with them, and pass `-D` to get some debug output.

e.g, 'Bind oneways to odd threads, 'defaults' to even threads: `./cpuminer ... -t 4 -1 4 --cpu-affinity-stride 2 --cpu-affinity-default-index 0 --cpu-affinity-oneway-index 1`
e.g.2, 'Bind oneways to the last 4 cpu's after the defaults' `./cpuminer ... -t 4 -1 4 --cpu-affinity-stride 1 --cpu-affinity-default-index 0 --cpu-affinity-oneway-index 4` (edited)

# RYZEN USERS pass `--ryzen`.

Ryzen's implementation of AVX2 is ... subpar.  Please pass `--ryzen` on the commandline to default to the AVX implementation.  Users reported ~25% gains.

### Connecting through a proxy

Use the --proxy option.

To use a SOCKS proxy, add a socks4:// or socks5:// prefix to the proxy host  
Protocols socks4a and socks5h, allowing remote name resolving, are also available since libcurl 7.18.0.

If no protocol is specified, the proxy is assumed to be a HTTP proxy.  
When the --proxy option is not used, the program honors the http_proxy and all_proxy environment variables.

GCC
=======
Some people have reported increases by using GCC 7.2.  Please note, this will replace your existing GCC installation, which may become unrecoverable if any errors occur in the `make` process.

To build and install GCC 7.2 on Ubuntu do the following:
* `apt-get -y install unzip flex`
* `wget https://github.com/gcc-mirror/gcc/archive/gcc-7_2_0-release.zip`
* `unzip gcc-7_2_0-release.zip`
* `cd gcc-gcc-7_2_0-release`
* `sudo ./contrib/download_prerequisites`
* `mkdir build && cd build`
* `../configure --enable-languages=c,c++ --disable-multilib`
* `make -j 8`
* `make install`


Credits
=======
CPUMiner-multi was forked from pooler's CPUMiner, and has been started by Lucas Jones.
* [tpruvot](https://github.com/tpruvot) added all the recent features and newer algorythmns
* [Wolf9466](https://github.com/wolf9466) helped with Intel AES-NI support for CryptoNight
* [FireWorm71](https://github.com/Fireworm71) helped with ARMv8 implementation, and memory optimizations.

Donations
=======
This miner does not include any automatic donation code.  Please donate if you find this code profitable.  A suggestion is about 3.5 days of mining time per year (1%).  If you prefer to mine on my behalf, please run your miner with the miner args below.
* FireWorm71:
  * Mining Donations: `./cpuminer -o stratum+tcp://stratum.poolsloth.com:3333 -u fireworm.donations -p x`
  * BTC: 1PPw16NEwMbGmobCcEyy9XhU5Uy7LTsRrZ
  * VRM: VB99zk5BGzAFsQvrrQeBBnZNGZYgmRfmSy
  * VRC: VYy4v95EfkJy7QnPSwfK7fhgWPM4RujbPf

License
=======
GPLv2.  See COPYING for details.
