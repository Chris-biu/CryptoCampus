declare const createCcWasmModule: (options?: {
  locateFile?: (file: string) => string
}) => Promise<unknown>

export default createCcWasmModule
