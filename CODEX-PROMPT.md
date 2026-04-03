Set up Emscripten IntelliSense from scratch for this VS Code C/C++ project.

Requirements:
- Detect or ask for the local EMSDK path if needed
- Create or update `.vscode/c_cpp_properties.json`
- Add Emscripten include paths
- Set `compilerPath` to `emcc`, `em++.bat`, or the correct local compiler
- Define `__EMSCRIPTEN__`
- Use a sane IntelliSense mode for my platform
- If `compile_commands.json` exists, prefer that instead
- Explain what you changed and why
- Do not break existing non-Emscripten configs unless necessary
- Verify headers like `<emscripten/emscripten.h>` resolve without red squiggles

Stricter version:

Audit this project and fully configure VS Code C/C++ IntelliSense for Emscripten. Create missing config files, preserve existing settings when possible, and output the final JSON files you changed. Verify headers like `<emscripten/emscripten.h>` resolve cleanly.

Optional extra checks:
- Look for `EMSDK` environment variable first
- Fall back to common local emsdk install paths if needed
- Keep the config portable where possible by using `${env:EMSDK}`
- Preserve existing non-Emscripten profiles and add a new `Emscripten` profile instead of replacing everything
- If using `compile_commands.json`, make sure the path is correct for this workspace


---

## Example Expected Output

```json
{
  "configurations": [
    {
      "name": "Emscripten",
      "includePath": [
        "${workspaceFolder}/**",
        "${env:EMSDK}/upstream/emscripten/system/include",
        "${env:EMSDK}/upstream/emscripten/system/lib/libc/include",
        "${env:EMSDK}/upstream/emscripten/system/lib/libcxx/include",
        "${env:EMSDK}/upstream/emscripten/system/lib/libcxxabi/include"
      ],
      "defines": [
        "__EMSCRIPTEN__"
      ],
      "compilerPath": "${env:EMSDK}/upstream/emscripten/emcc",
      "cStandard": "c11",
      "cppStandard": "c++17",
      "intelliSenseMode": "linux-clang-x64"
    }
  ],
  "version": 4
}
```

## Test File (Validation)

```c
// test.c
#include <emscripten/emscripten.h>
#include <stdio.h>

int main() {
    printf("Hello from WASM
");
    emscripten_run_script("console.log('WASM running')");
    return 0;
}
```

## Additional Instruction

If `compile_commands.json` exists, ignore manual includePath and use it instead.

