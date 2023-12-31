--[[
Edit this file in order to enable models for statically-linked functions.
Models drastically reduce path explosion at the expense of more complex expressions.

Suppose that the binary you want to analyze contains at address 0x1234 a function
that computes a standard CRC32 checksum. To enable the model for the CRC32 function,
add the following lines:

g_function_models["Target(path=/home/cyfi/fangs/proj_ddr/pipeline/../ddr_samples_ls/second_batch/fea7a448b1987dffd751b4b82623832719a534320406234fc8daf78a4c402f99,arch=i386)"] = {}
g_function_models["Target(path=/home/cyfi/fangs/proj_ddr/pipeline/../ddr_samples_ls/second_batch/fea7a448b1987dffd751b4b82623832719a534320406234fc8daf78a4c402f99,arch=i386)"][0x1234] = {
    xor_result=true, --Must be true for standard CRC32
    type="crc32"
}

Function models assume specific calling conventions and function arguments.
They may not work with different variations of the implementation of the
original function. For example, the CRC32 model only supports one type of
CRC32 algorithm and only functions that have the following signature:

    uint32 crc32(uint8_t *buf, unsigned size)

Please refer to StaticFunctionModels.cpp file for details on their implementation.
]]--

g_function_models["Target(path=/home/cyfi/fangs/proj_ddr/pipeline/../ddr_samples_ls/second_batch/fea7a448b1987dffd751b4b82623832719a534320406234fc8daf78a4c402f99,arch=i386)"] = {}