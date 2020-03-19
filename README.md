# Mousse

Mousse is a platform to analyze programs interacting with complex environments that cannot be modeled nor virtualized (untamed environments) using selective symbolic execution (SSE). 

Before you try Mousse, there are some questions we would like to answer.

**Why do I need Mousse to analyze programs? Can I just use S2E?**

Mousse was invented with the goal of analyzing real-world complex programs that require interaction with complex environments. The environments here cannot be modeled nor virtualized. One example of such environments is customized hardware components. To correctly analyze a program that interacts with the underlying environment, S2E needs the virtual machine to virtualize the underlying environment including its hardwares. But it is almost impossible to virtualize customized hardware components and the corresponding device drivers usually don't exist in existing virtual machines. Mousse can easily analyze such programs without modeling and virtualizing the underlying environments.

**Does Mousse support the analysis of different programming languages?**

Mousse now just supports native programs (c/c++).
      
**Can Mousse analyze close-sourced binaries?**

Yes, Mousse is best suitable for proprietary libraries.

**How does Mousse detect bugs?**

We developed multiple memory checkers in Mousse to detect bugs and vulnerabilities. Examples are double-free checker, use-after-free checker.

**What kind of architecture does Mousse support?**

Mousse now supports 32-bit ARM.

*More techinical details, please refer to our paper: [Mousse](to appear in EuroSys'20)

Now try Mousse if you are interested!

# Hardware prerequisites

Mousse supports distributed execution. To run Mousse, you will need:
1. One server that runs Ubuntu 16.04.3 LTS. Other Ubuntu versions might also work, but not guaranted. 
2. At least one Pixel 3 (client) that runs blueline (android-9.0.0_r30 from AOSP). Other Android phones would also work, but this instruction is based on Pixel 3. 

# Set up the hardwares
* On the server, you need to have git, gcc, adb, fastboot, python and libelf-dev installed already. If not, run:
```
      sudo apt-get install gcc git android-tools-adb android-tools-fastboot python libelf-dev
```
* For all the Pixel 3 you would like to use as Mousse clients, you will need to gain root access to them. Follow the instruction [here](https://source.android.com/setup/build/running) to unlock your Pixel 3. Then you need to build your custom blueline image from source to gain root access. Follow the instruction [here](https://source.android.com/setup/build/building). To avoid unnecessary troubles, please use this version: android-9.0.0_r30.

# Set up dependencies for Mousse 

Before cross-compiling Mousse for ARM, you need: First, create an standalone toolchain from Android NDK. Second: build the dependent libraries needed by Mousse. Run to download android-ndk:
```
      wget https://dl.google.com/android/repository/android-ndk-r14b-linux-x86_64.zip
      unzip android-ndk-r14b-linux-x86_64.zip
```
Install the toolchain to ~/Mousse/mousse_dependencies
```
      mkdir ~/Mousse
      ~/android-ndk-r14b/build/tools/make_standalone_toolchain.py --arch arm --api 24 --install-dir ~/Mousse/mousse_dependencies
```
Checkout Mousse scripts:
```
      cd ~/Mousse
      git clone https://github.com/trusslab/mousse_scripts.git
```
Dowload the prebuilt libraries from [here](https://drive.google.com/file/d/1XfnJH2A5YwGGpVFbI4pJr-owWDYo19yF/view?usp=sharing). Then run the build_mousse_deps.sh script to build Mousse's dependent libraries and install them to the toolchain sysroot. 
```
      mv mousse_prebuilt_deps.tar.gz ~/Mousse/mousse_dependencies
      mousse_scripts/build_mousse_deps.sh ~/Mousse/mousse_dependencies
```
# Build Mousse client from source code
Get Mousse client source code:
```
      git clone https://github.com/trusslab/mousse.git mousse_source
      git clone https://github.com/trusslab/mousse_qemu.git
```
Run the commands to build Mousse client source code:
```
      cd ~/Mousse
      mkdir mousse_build
      cd mousse_build
      ../mousse_scripts/configure_build_mousse.sh
```
# Build Mousse server from source code
Run the commands to build Mousse server source code:
```
      cd ~/Mousse
      ./mousse_source/mousse_server/build.sh
```
# Test a toy program
Add your Pixel 3 ID to devices.txt (You can add more than one if you want to use multiple phones. Run 'adb devices' to get all attached device IDs). To test a toy program we provided in ./mousse_testing/toy_program, run the commands to set up your client:
```
      cd ~/Mousse/mousse_scripts/testing
      ./mousse.sh -s -o target_toy
```
Run the commands to build the toy program and push it to the device:
```
      cd ./toy_program
      build.sh toy.c
      adb -s <device_id> push ./toy /data/local/mousse/target_toy
```
The toy program has 8 execution paths in total. The concurrent threshold is set to 3 by default in s2e-configu.lua (i.e. It allows 2 execution paths run concurrently). Run the command to test the toy program:
```
      ./mousse.sh -d 1 -o target_toy /data/local/mousse/target_toy/toy
```
If you have multiple phones available, start a new terminal for each one then run ('n' is the device index in devices.txt):
```
      ./mousse.sh -d <n> -o target_toy /data/local/mousse/target_toy/toy
```
Choose 'c' if you see "A mousse server instance is already running" shows and waits for your action, which means you want to connect to the same mousse server instance that has been started.
You can monitor the server's progress in server.log. Or you can run 'screen -r' to resume the server's screen session.
When the testing is finished, you will see print like "server has no data available". Press ctrl z to stop testing. 

# Enable additional Mousse features
Please refer to [here](https://github.com/trusslab/mousse_scripts/blob/master/testing/README) if you want to try mousse checkers, mousse coverage plugin or test a real Android service.

# Acknowledgments
The work was supported by NSF Award #1763172
