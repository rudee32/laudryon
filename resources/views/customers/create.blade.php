<x-app-layout>
    <div class="bg-white rounded-xl shadow-sm">
        <div class="p-6 border-b border-gray-100">
            <h2 class="text-lg font-semibold text-gray-800">Tambah Pelanggan Baru</h2>
        </div>
        
        <div class="p-6">
            <form action="{{ route('customers.store') }}" method="POST">
                @csrf
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <!-- Nama -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Nama</label>
                        <input type="text" name="name" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]" required>
                    </div>

                    <!-- No. Telepon -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">No. Telepon</label>
                        <input type="tel" name="phone" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]" required>
                    </div>

                    <!-- Alamat -->
                    <div class="md:col-span-2">
                        <label class="block text-sm font-medium text-gray-700 mb-2">Alamat</label>
                        <textarea name="address" rows="3" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]" required></textarea>
                    </div>
                </div>

                <div class="mt-6 flex justify-end">
                    <a href="{{ route('customers.index') }}" class="bg-gray-100 text-gray-800 px-4 py-2 rounded-lg text-sm font-semibold mr-2">Batal</a>
                    <button type="submit" class="bg-[#00B4D8] hover:bg-[#0096B4] text-white px-4 py-2 rounded-lg text-sm font-semibold">
                        Simpan Pelanggan
                    </button>
                </div>
            </form>
        </div>
    </div>
</x-app-layout> 