# BDS Development Helper
An IDA plugin to help you develop with bedrock dedicated server, designed specifically for [LiteLoaderBDS](https://github.com/LiteLDev/LiteLoaderBDS).

### Features

 - [x] Automatically generate Hook & SymCall code blocks.

> 1. Install dependent libraries.
> ```
> pip install pyperclip
> ```
> 2. Download `BDSDevHelper.py` and put it in the `path/to/ida/plugins` folder
> 3. Run IDA, observe the output like:
> ```
> [*] BDS Dev Helper is loaded, ver 1.x.x.
> [*] By: RedbeanW.
> ```
>  - Right click the function name, enjoy it!
> 
> ![1](https://user-images.githubusercontent.com/29711228/175335921-13723762-d10b-44c7-b43c-740d0e6b5b5c.png)

 - [x] Export all enum, structure, and local types data.

> 1. Install the IDA plugin using the method described above.
> 2. Go Edit/BDSDevHelper/Export... to export all til data.
> 3. You can use Docs.py to generate documents from the exported data.

 - [x] Automatically analyze the size of a structure based on its constructor, and export data for comparison with other versions or generate reports.

> 1. Install the IDA plugin using the method described above.
> 2. Go to Edit/BDSDevHelper/Analyze... to analyze and generate structure size data.
> 3. You can use TilChangedReporter.py to generate reporter from the exported data.

### ATTENTION
 - **Only** use to analyze BDS.
 - MIT License.
