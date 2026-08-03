# TÌM HIỂU VỀ CẤU TRÚC PE FILE

## Tổng quan về định dạng PE

### Khái niệm PE file
- PE file format (Portable Executable File Format) là một định dạng file riêng của Win32. Tất cả các dạng file có thể chạy và thực thi trên Win32 như `.exe`, `.dll`,... đều là định dạng PE. 
- File PE được chia làm hai phần **Header** và **Section**, trong đó **Header** có vai trò lưu các giá trị định dạng file và các offset của các section trong phần **Section**.

### Vai trò của PE file
PE đóng vai trò nền tảng trong kiến trúc hệ điều hành Windows, cung cấp một tiêu chuẩn cho các đối tượng thực thi như file `.exe`, `.dll`, `.sys`. Đặt trên nền tảng kế thừa và phát triển từ định dạng **COFF** (Common Object File Format) của Unix, cấu trúc PE được mở rộng nhằm tối ưu hóa tính linh hoạt và khả năng tương thích hệ thống (Microsoft Corporation, 2018). Vai trò của PE file được thể hiện qua các khía cạnh kỹ thuật cốt lõi sau:

- **Chuẩn hóa quy trình thực thi:** PE file thiết lập một giao thức thống nhất cho việc khởi tạo tiến trình. Hệ thống thông tin trong các tiêu đề (Headers)—như `Magic Number`, `Machine Type`, và `Subsystem`—cung cấp cho bộ tải hệ điều hành (OS Loader) các dữ liệu nguyên thủy cần thiết để xác thực tính hợp lệ và cấu hình môi trường chạy phù hợp (Russinovich et al., 2012).
- **Tổ chức và quản lý bộ nhớ ảo:** PE file triển khai mô hình phân đoạn (section-based layout) nhằm phân định rõ ràng mã máy (`.text`), dữ liệu khởi tạo (`.data`), và tài nguyên nhúng (`.rsrc`). Kiến trúc này không chỉ tối ưu hóa việc định tuyến bộ nhớ mà còn cho phép OS Loader áp dụng các đặc tính phân quyền truy cập (Read/Write/Execute) riêng biệt cho từng phân vùng theo thuộc tính chức năng của chúng (Eilam, 2011; Perriot & Ferrie, 2004).
- **Định vị và định tuyến địa chỉ linh hoạt:** Thông qua việc sử dụng các chỉ số Địa chỉ Virtual Tương đối (Relative Virtual Address - RVA) kết hợp với Bảng tái định vị (Relocation Table), PE file đóng vai trò như một bản chỉ dẫn kỹ thuật. Cơ chế này cho phép OS Loader điều chỉnh các tham chiếu địa chỉ tuyệt đối trong mã máy tại thời điểm nạp (runtime load) khi hình ảnh tệp không thể đặt tại địa chỉ ưu tiên (`ImageBase`), đảm bảo tính toàn vẹn của tiến trình (Kuacharoen, 2009).
- **Điều phối liên kết động và tính mô-đun:** PE file duy trì cấu trúc Bảng nhập địa chỉ (Import Address Table - IAT) và Bảng xuất (Export Table). Mô hình này cho phép các ứng dụng chia sẻ tài nguyên mã nguồn, giảm thiểu dung lượng lưu trữ, và tạo nền tảng cho hệ sinh thái thư viện chia sẻ (DLL) của Windows (Anderson, 2012; Sikorski & Honig, 2012).
- **Tích hợp các cơ chế an ninh cấp thấp:** Bản thân cấu trúc PE được thiết kế để hỗ trợ trực tiếp các tính năng bảo mật của phần cứng và kernel, bao gồm Bảng chữ ký số (Digital Signature Table), ngăn chặn thi hành mã trên vùng dữ liệu (Data Execution Prevention - DEP), và ngẫu nhiên hóa sơ đồ không gian địa chỉ (Address Space Layout Randomization - ASLR). Sự tích hợp này tạo thành lớp phòng thủ cơ sở chống lại các kỹ thuật khai thác như tràn bộ đệm (buffer overflow) hay chèn mã độc (code injection) (Szor, 2005; Johnson & Keromytis, 2011).

## Cấu trúc của PE File

![alt text](image.png)

Ở mức cơ bản, một PE file gồm có 2 phần: đoạn mã (code) và dữ liệu (data). Một chương trình hay ứng dụng chạy trên nền tảng Windows NT gồm có 9 sections được xác định trước, bao gồm `.text`, `.bss`, `.data`, `.rdata`, `.rsrc`, `.edata`, `.idata`, `.pdata` , và `.debug.`. Tuy nhiên không phải chương trình nào cũng cần đủ 9 sections này, và đa số chương trình sẽ được định nghĩa với nhiều sections hơn để phù hợp với cách sử dụng của chúng.

Cấu trúc của một file PE trên đĩa và khi được nạp vào bộ nhớ RAM có sự tương đồng lớn về các thành phần, nhưng không hoàn toàn giống hệt nhau.

Windows Loader sẽ quyết định phần dữ liệu nào cần được ánh xạ (map) vào bộ nhớ và phần nào có thể bỏ qua. Những dữ liệu không được ánh xạ vào RAM (chẳng hạn như Debug Information) thường được đặt ở cuối file trên đĩa.

Vị trí (offset) của các dữ liệu trong file trên đĩa sẽ khác với địa chỉ của chúng khi nằm trong RAM vì cơ chế quản lý bộ nhớ ảo dựa trên trang (Paging) của Windows:

- **Căn chỉnh trang (Section Alignment)**: Khi nạp các section vào RAM, hệ thống căn chỉnh chúng theo kích thước trang bộ nhớ (thường là 4KB). Mỗi section sẽ bắt đầu ở một trang bộ nhớ mới.

- **Cấp phát bộ nhớ**: Một trường trong PE Header (SizeOfImage) sẽ thông báo cho hệ điều hành biết tổng dung lượng bộ nhớ ảo cần cấp phát để ánh xạ toàn bộ file PE vào RAM.

### Header

#### DOS Header
Tất cả các PE file đều bắt đầu bằng **DOS Header** (IMAGE_DOS_HEADER), có kích thước cố định **64 bytes** (`0x40` bytes).

Mục đích chính của **DOS Header** là đảm bảo khả năng tương thích ngược (backward compatibility) với hệ điều hành MS-DOS 16-bit cổ điển, đồng thời cung cấp điểm neo dẫn tới cấu trúc thực thi Windows thực sự (NT Headers).

**DOS Header** là một cấu trúc được định nghĩa trong `windows.inc` hoặc `winnt.h`, gồm 19 thành phần (members):

```c++
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;      // Magic number ("MZ" - 0x5A4D) - OFFSET: 0x00
    WORD  e_cblp;       // Bytes on last page of file   - OFFSET: 0x02
    WORD  e_cp;         // Pages in file    - OFFSET: 0x04
    WORD  e_crlc;       // Relocations  - OFFSET: 0x06
    WORD  e_cparhdr;    // Size of header in paragraphs - OFFSET: 0x08
    WORD  e_minalloc;   // Minimum extra paragraphs needed  - OFFSET: 0x0a
    WORD  e_maxalloc;   // Maximum extra paragraphs needed  - OFFSET: 0x0c
    WORD  e_ss;         // Initial (relative) SS value  - OFFSET: 0x0c
    WORD  e_sp;         // Initial SP value - OFFSET: 0x10
    WORD  e_csum;       // Checksum - OFFSET: 0x12
    WORD  e_ip;         // Initial IP value - OFFSET: 0x14
    WORD  e_cs;         // Initial (relative) CS value  - OFFSET: 0x16
    WORD  e_lfarlc;     // File address of relocation table - OFFSET: 0x18
    WORD  e_ovno;       // Overlay number   - OFFSET: 0x1a
    WORD  e_res[4];     // Reserved words   - OFFSET: 0x1c
    WORD  e_oemid;      // OEM identifier (for e_oeminfo)   - OFFSET: 0x24
    WORD  e_oeminfo;    // OEM information; e_oemid specific    - OFFSET: 0x26
    WORD  e_res2[10];   // Reserved words   - OFFSET: 0x28
    LONG  e_lfanew;     // File address of new exe header (NT Headers)  - OFFSET: 0x3c
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

Trong đó có 2 trường mang giá trị quyết định với Windows OS hiện đại và các Reverse Engineering Tool:

- `e_magic` (2 bytes - OFFSET `0x00`):

    - Trường này được gọi là **Magic Number** hoặc **DOS Signature**.
    - Giá trị của trường này luôn là `0x5A4D` tương ứng với 2 kí tự ASCII **"MZ"**
    - Windows Loader sẽ dựa vào 2 bytes này (`0x5a` và `0x4d`) để xác định đây có phải là một file thực thi hợp lệ hay không

    ![alt text](image-1.png)

- `e_lfanew` (4 bytes - OFFSET `0x3c`):

    - Trường nằm cuối của DOS Header
    - Chứa **File Offset** (địa chỉ con trỏ) trỏ trực tiếp đến điểm bắt đầu của NT Headers.
    - Đây là trường quan trọng nhất giúp OS Loader bỏ qua phần dữ liệu DOS dư thừa để đọc thông tin nạp file 32-bit/64-bit.

Giá trị `DWORD` cuối cùng trước điểm bắt đầu DOS Stub chứa những giá trị `00 01 00 00`. Để ý đến trật tự byte, điều này giúp ta biết `00 00 01 00h` là những offset nơi mà PE Header bắt đầu. PE Header bắt đầu với phần signatures của nó là `50h, 45h, 00h, 00h` (Các kí tự “PE” được đi kèm bới các giá trị tận cùng là 0)

![alt text](image-2.png)

#### NT Header

NT Header hay `IMAGE_NT_HEADERS` là cấu trúc quan trọng nhất trong PE Header, đóng vai trò như "bộ não" chứa toàn bộ thông tin vận hành cốt lõi mà Windows Loader cần để nạp một tệp thực thi vào bộ nhớ (RAM).

Địa chỉ của `IMAGE_NT_HEADERS` được tính theo công thức:

$$Address = BaseAddress + Offset$$
Trong đó: $BaseAddress$ - địa chỉ gốc của file được lưu tại trường `e_lfanew`trong DOS Header

Tuỳ vào kiến trúc PE32 hay PE32+ (tương ứng với tệp 32-bit hay 64-bit), cấu trúc này sẽ được định nghĩa theo cách khác nhau. Cụ thể:

- Đối với `PE32`:
    ```c++
    typedef struct _IMAGE_NT_HEADERS {
        DWORD Signature;                    // PE Signature ("PE\0\0")
        IMAGE_FILE_HEADER FileHeader;       // Thông tin tổng quan file
        IMAGE_OPTIONAL_HEADER32 OptionalHeader; // Thông tin nạp bộ nhớ & cấu trúc dữ liệu
    } IMAGE_NT_HEADER32, *PIMAGE_NT_HEADER;
    ```

- Đối với `PE32+`:
    ```c++
    typedef struct _IMAGE_NT_HEADERS64 {
        DWORD Signature;                    // PE Signature ("PE\0\0")
        IMAGE_FILE_HEADER FileHeader;       // Thông tin tổng quan file
        IMAGE_OPTIONAL_HEADER64 OptionalHeader; // Thông tin nạp bộ nhớ & cấu trúc dữ liệu
    } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
    ```

Trong đó:
- 4 bytes `Signature` giữ giá trị cố định `0x00004550` (đổi sang ASCII text là `PE\0\0`) được dùng để xác định đây là một NT headers hợp lệ.
- 20 bytes `FileHeader` dùng để chứa thông tin cấu hình vật lý của file, bao gồm:

    ```c++
    typedef struct _IMAGE_FILE_HEADER {
        WORD Machine;
        WORD NumberOfSections;
        ULONG TimeDateStamp;
        ULONG PointerToSymbolTable;
        ULONG NumberOfSymbols;
        WORD SizeOfOptionalHeader;
        WORD Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
    ```
    
    - `Machine`: Xác định kiến trúc phần cứng
    - `NumberOfSections`: Số lượng các section (`.text`, `.data`, `.rsrc`...). Loader dùng thông tin này để biết có bao nhiêu Section Header ở ngay sau NT Header.
    - `TimeDateStamp`: Đấu mốc thời gian file được biên dịch (Epoch time).
    - `SizeOfOptionalHeader`: Kích thước của `OptionalHeader` đi ngay sau nó (thường là `0xE0` cho 32-bit và `0xF0` cho 64-bit).
    - `Characteristics`: Cờ hiệu trạng thái file (VD: `0x0002` = Executable, `0x2000` = DLL file).

- 224 bytes `OptionalHeader` chứa thông tin về Logic bên trong của PE file, đồng thời đây là phần quan trọng nhất quyết định cách data được nạp lên RAM

    ![alt text](image-3.png)

    - **AddressOfEntryPoint – RVA** (địa chỉ ảo tương đối) là khoảng cách (offset) từ địa chỉ nạp gốc (`ImageBase`) đến một vị trí dữ liệu hoặc lệnh trong RAM Memory. Nếu như muốn làm thay đổi luồng của thứ tự thực hiện, cần phải thay đổi lại giá trị trong trường này thành một RVA mới và do đó câu lệnh tại giá trị RVA mới này sẽ được thực thi đầu tiên. Công thức:

    $$VA = ImageBase + RVA$$

    - **ImageBase** (địa chỉ nạp được ưu tiên). Giá trị của address này là mặc định. Cụ thể, đối với tệp `.exe` 32-bit thường là `0x00400000`, 64-bit là `0x0000000140000000`. Với tệp `.dll` thường là `0x10000000`.

        > Cơ chế ASLR (Address Space Layout Randomization): Nếu cờ bảo mật ASLR được bật (hoặc địa chỉ ImageBase bị xung đột với ứng dụng khác), Windows Loader sẽ nạp tệp vào một địa chỉ ảo ngẫu nhiên khác. Lúc này, hệ thống phải dựa vào bảng .reloc để tính toán lại địa chỉ thực tế.

    - **SectionAlignment** (Độ căn chỉnh bộ nhớ ảo). Field này có nhiệm vụ quy định kích thước khối bộ nhớ tối thiểu khi từng Section được ánh xạ lên RAM.

        - Giá trị phổ biến: `0x1000` bytes (4 KB) - đúng bằng kích thước 1 trang Memory Page trên kiến trúc `x86/64`
        - Cơ chế: Nếu một Section có kích thước dữ liệu thực tế chỉ là 1.5 KB, Windows Loader vẫn phải cấp phát trọn vẹn 4 KB trên RAM cho Section đó. Phần dư thừa còn lại sẽ được chèn các byte trống (`0x00` - Padding). 

    - **SizeOfImage** xác định tổng dung lượng bộ nhớ ảo (RAM) mà Windows Loader phải đặt trước (reserve) để chứa toàn bộ PE File (bao gồm cả Headers và tất cả các Sections). Công thức:

    $$SizeOfImage = \sum (\text{Kích thước các Section đã căn chỉnh theo } SectionAlignment) + PE\_Header$$

#### Data Directory
**DataDirectory** là một mảng gồm 16 phần tử nằm ở cuối cấu trúc `IMAGE_OPTIONAL_HEADER`. Mỗi phần tử là một cấu trúc `IMAGE_DATA_DIRECTORY` gồm 8 bytes:

```c++
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress; // Địa chỉ RVA trỏ đến bảng dữ liệu
    DWORD Size;           // Kích thước của bảng dữ liệu (bytes)
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

