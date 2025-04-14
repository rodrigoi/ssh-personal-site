import { describe, expect, test } from "bun:test";
import { concatUint8Arrays, stringToUint8Array, writeUint32BE } from "./index";

describe("concatUint8Arrays", () => {
  test("should concatenate two arrays", () => {
    const arr1 = new Uint8Array([1, 2, 3]);
    const arr2 = new Uint8Array([4, 5, 6]);
    const result = concatUint8Arrays(arr1, arr2);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
  });

  test("should concatenate multiple arrays", () => {
    const arr1 = new Uint8Array([1]);
    const arr2 = new Uint8Array([2]);
    const arr3 = new Uint8Array([3]);
    const result = concatUint8Arrays(arr1, arr2, arr3);
    expect(result).toEqual(new Uint8Array([1, 2, 3]));
  });

  test("should handle empty arrays", () => {
    const arr1 = new Uint8Array([]);
    const arr2 = new Uint8Array([1, 2, 3]);
    const result = concatUint8Arrays(arr1, arr2);
    expect(result).toEqual(new Uint8Array([1, 2, 3]));
  });

  test("should handle all empty arrays", () => {
    const arr1 = new Uint8Array([]);
    const arr2 = new Uint8Array([]);
    const result = concatUint8Arrays(arr1, arr2);
    expect(result).toEqual(new Uint8Array([]));
  });

  test("should handle large arrays", () => {
    const arr1 = new Uint8Array(1000).fill(1);
    const arr2 = new Uint8Array(1000).fill(2);
    const result = concatUint8Arrays(arr1, arr2);
    expect(result.length).toBe(2000);
    expect(result[0]).toBe(1);
    expect(result[999]).toBe(1);
    expect(result[1000]).toBe(2);
    expect(result[1999]).toBe(2);
  });

  test("should maintain array values", () => {
    const arr1 = new Uint8Array([255, 0, 128]);
    const arr2 = new Uint8Array([1, 2, 3]);
    const result = concatUint8Arrays(arr1, arr2);
    expect(result).toEqual(new Uint8Array([255, 0, 128, 1, 2, 3]));
  });
});

describe("stringToUint8Array", () => {
  test("should convert ASCII string to Uint8Array", () => {
    const str = "Hello, World!";
    const result = stringToUint8Array(str);
    expect(result).toEqual(
      new Uint8Array([
        72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33,
      ])
    );
  });

  test("should convert empty string to empty Uint8Array", () => {
    const str = "";
    const result = stringToUint8Array(str);
    expect(result).toEqual(new Uint8Array([]));
  });

  test("should handle Unicode characters", () => {
    const str = "Hello 🌍";
    const result = stringToUint8Array(str);
    expect(result).toEqual(
      new Uint8Array([72, 101, 108, 108, 111, 32, 240, 159, 140, 141])
    );
  });

  test("should handle special characters", () => {
    const str = "!@#$%^&*()";
    const result = stringToUint8Array(str);
    expect(result).toEqual(
      new Uint8Array([33, 64, 35, 36, 37, 94, 38, 42, 40, 41])
    );
  });

  test("should handle newlines and whitespace", () => {
    const str = "Hello\nWorld\t";
    const result = stringToUint8Array(str);
    expect(result).toEqual(
      new Uint8Array([72, 101, 108, 108, 111, 10, 87, 111, 114, 108, 100, 9])
    );
  });

  test("should handle non-printable characters", () => {
    const str = "\x00\x01\x02\x03";
    const result = stringToUint8Array(str);
    expect(result).toEqual(new Uint8Array([0, 1, 2, 3]));
  });
});

describe("writeUint32BE", () => {
  test("should write zero correctly", () => {
    const result = writeUint32BE(0);
    expect(result).toEqual(new Uint8Array([0, 0, 0, 0]));
  });

  test("should write maximum 32-bit unsigned integer", () => {
    const result = writeUint32BE(0xffffffff);
    expect(result).toEqual(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
  });

  test("should write a simple number correctly", () => {
    const result = writeUint32BE(0x12345678);
    expect(result).toEqual(new Uint8Array([0x12, 0x34, 0x56, 0x78]));
  });

  test("should handle numbers with leading zeros", () => {
    const result = writeUint32BE(0x0000abcd);
    expect(result).toEqual(new Uint8Array([0x00, 0x00, 0xab, 0xcd]));
  });

  test("should handle numbers with trailing zeros", () => {
    const result = writeUint32BE(0xabcd0000);
    expect(result).toEqual(new Uint8Array([0xab, 0xcd, 0x00, 0x00]));
  });

  test("should handle numbers with alternating bits", () => {
    const result = writeUint32BE(0xaaaaaaaa);
    expect(result).toEqual(new Uint8Array([0xaa, 0xaa, 0xaa, 0xaa]));
  });

  test("should handle numbers with all bits set in each byte", () => {
    const result = writeUint32BE(0xff00ff00);
    expect(result).toEqual(new Uint8Array([0xff, 0x00, 0xff, 0x00]));
  });

  test("should handle numbers with minimum value", () => {
    const result = writeUint32BE(1);
    expect(result).toEqual(new Uint8Array([0x00, 0x00, 0x00, 0x01]));
  });

  test("should handle numbers with maximum value in each byte", () => {
    const result = writeUint32BE(0xff000000);
    expect(result).toEqual(new Uint8Array([0xff, 0x00, 0x00, 0x00]));
  });
});
