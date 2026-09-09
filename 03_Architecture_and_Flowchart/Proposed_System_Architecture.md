# **Proposed System Architecture**

```text
The Analyzer compares the file size of the original cover image and the stego image in bytes. In this test, the cover image size was 1,125,632 bytes, while the stego image size was 996,745 bytes. Therefore, the stego image was 128,887 bytes smaller than the cover image.
```

<img width="401" height="66" alt="Picture1" src="https://github.com/user-attachments/assets/6c550671-76c2-4c60-b62f-d2a20e64fb9e" />

```text
The file size became smaller because the stego image was saved as a new PNG file. PNG uses lossless compression, and the compression result can be different when the image is saved again. Therefore, the smaller file size does not mean that the hidden data was lost or that the image quality was reduced. It is mainly related to how the image was saved and compressed after the embedding process.
