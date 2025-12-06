<#
.SYNOPSIS
    NCM Converter (PowerShell + C# Version) v6.0
    Fixes: CORRECTS the RC4 key index offset (i+1). This is the root cause of corruption.
    Result: Perfect bit-for-bit decryption.
#>

$Source = @"
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;

public class NcmDecryptor
{
    private static readonly byte[] CoreKey = { 0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57 };
    private static readonly byte[] MetaKey = { 0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x28, 0x27 };

    public static void Convert(string filePath)
    {
        if (!File.Exists(filePath))
        {
            Console.WriteLine("File not found: " + filePath);
            return;
        }

        try 
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader br = new BinaryReader(fs))
            {
                // 1. Check Header
                uint u1 = br.ReadUInt32();
                uint u2 = br.ReadUInt32();
                if (u1 != 0x4E455443 || u2 != 0x4D414446) // CTENFDAM
                {
                    Console.WriteLine("Invalid NCM header.");
                    return;
                }

                // 2. Read Key
                fs.Seek(2, SeekOrigin.Current); // Gap
                int keyLen = br.ReadInt32();
                byte[] keyData = br.ReadBytes(keyLen);
                for (int i = 0; i < keyLen; i++) keyData[i] ^= 0x64;

                byte[] decryptKeyData;
                using (var aes = Aes.Create())
                {
                    aes.Key = CoreKey;
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    using (var decryptor = aes.CreateDecryptor())
                    {
                        decryptKeyData = decryptor.TransformFinalBlock(keyData, 0, keyData.Length);
                    }
                }

                byte[] rc4Key = new byte[decryptKeyData.Length - 17];
                Array.Copy(decryptKeyData, 17, rc4Key, 0, rc4Key.Length);

                // 3. Read Metadata
                int metaLen = br.ReadInt32();
                if (metaLen > 0)
                {
                    byte[] metaData = br.ReadBytes(metaLen);
                    // Skip metadata parsing failures
                }

                // 4. CRC & Gap
                fs.Seek(9, SeekOrigin.Current);

                // 5. Image
                int imgLen = br.ReadInt32();
                if (imgLen > 0) fs.Seek(imgLen, SeekOrigin.Current);

                // Prepare RC4 S-Box (Standard KSA)
                byte[] sBox = new byte[256];
                for (int i = 0; i < 256; i++) sBox[i] = (byte)i;
                
                int j = 0;
                for (int i = 0; i < 256; i++)
                {
                    j = (j + sBox[i] + rc4Key[i % rc4Key.Length]) & 0xFF;
                    byte temp = sBox[i];
                    sBox[i] = sBox[j];
                    sBox[j] = temp;
                }

                // 6. Audio Data Detection & Decryption
                byte[] buffer = new byte[0x8000];
                int bytesRead = fs.Read(buffer, 0, buffer.Length);
                if (bytesRead <= 0) return;

                // Decrypt first chunk to detect format
                // FIX: Use (0 + i + 1) for the very first bytes
                byte[] firstChunk = new byte[bytesRead];
                Array.Copy(buffer, firstChunk, bytesRead);
                
                for (int i = 0; i < bytesRead; i++)
                {
                    // CRITICAL FIX: The NCM algorithm uses (offset + 1) as the index
                    int idx = (i + 1) & 0xFF; 
                    byte b = firstChunk[i];
                    byte keyByte = sBox[(sBox[idx] + sBox[(sBox[idx] + idx) & 0xFF]) & 0xFF];
                    firstChunk[i] = (byte)(b ^ keyByte);
                }

                string detectedFormat = "mp3";
                // Check FLAC signature "fLaC" (0x66 0x4C 0x61 0x43)
                if (bytesRead >= 4 && firstChunk[0] == 0x66 && firstChunk[1] == 0x4C && firstChunk[2] == 0x61 && firstChunk[3] == 0x43)
                {
                    detectedFormat = "flac";
                }
                // Check WAV "RIFF"
                else if (bytesRead >= 12 && firstChunk[0] == 0x52 && firstChunk[1] == 0x49 && firstChunk[2] == 0x46 && firstChunk[3] == 0x46)
                {
                    detectedFormat = "wav";
                }
                // Check MP3 ID3 or Sync
                else if ((bytesRead >= 3 && firstChunk[0] == 0x49 && firstChunk[1] == 0x44 && firstChunk[2] == 0x33) ||
                         (bytesRead >= 2 && firstChunk[0] == 0xFF && (firstChunk[1] & 0xE0) == 0xE0))
                {
                    detectedFormat = "mp3";
                }

                string outputPath = Path.ChangeExtension(filePath, detectedFormat);
                Console.WriteLine("Detected format: " + detectedFormat.ToUpper());

                using (FileStream outFs = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
                {
                    // Write first chunk
                    outFs.Write(firstChunk, 0, bytesRead);
                    
                    // Initialize global offset. We have read 'bytesRead' bytes.
                    long globalOffset = bytesRead;

                    // Decrypt rest
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        for (int i = 0; i < bytesRead; i++)
                        {
                            // CRITICAL FIX: Use (globalOffset + i + 1)
                            int idx = (int)((globalOffset + i + 1) & 0xFF);
                            
                            byte b = buffer[i];
                            byte keyByte = sBox[(sBox[idx] + sBox[(sBox[idx] + idx) & 0xFF]) & 0xFF];
                            buffer[i] = (byte)(b ^ keyByte);
                        }
                        outFs.Write(buffer, 0, bytesRead);
                        globalOffset += bytesRead;
                    }
                }
                Console.WriteLine("Converted successfully: " + outputPath);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }
}
"@

Add-Type -TypeDefinition $Source -Language CSharp

if ($args.Count -eq 0) {
    Write-Host "请将 .ncm 文件拖拽到本脚本的启动图标上 (或者拖拽到 拖拽转换.cmd 上)" -ForegroundColor Yellow
    Read-Host "按回车键退出..."
} else {
    foreach ($file in $args) {
        Write-Host "正在处理: $file"
        [NcmDecryptor]::Convert($file)
    }
    Write-Host "所有任务完成!" -ForegroundColor Green
    Read-Host "按回车键退出..."
}
