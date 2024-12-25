<x-app-layout>
    <div class="bg-white rounded-xl shadow-sm">
        <div class="p-6 border-b border-gray-100">
            <h2 class="text-lg font-semibold text-gray-800">Tambah Layanan Baru</h2>
        </div>
        
        <div class="p-6">
            <form action="{{ route('services.store') }}" method="POST">
                @csrf
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <!-- Nama Layanan -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Nama Layanan</label>
                        <input type="text" name="name" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]" required>
                    </div>

                    <!-- Harga per Kg -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Harga per Kg</label>
                        <input type="number" name="price_per_kg" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]" required>
                    </div>

                    <!-- Estimasi Hari -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Estimasi Hari</label>
                        <input type="number" name="estimated_days" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]" required>
                    </div>

                    <!-- Deskripsi -->
                    <div class="md:col-span-2">
                        <label class="block text-sm font-medium text-gray-700 mb-2">Deskripsi</label>
                        <textarea name="description" rows="3" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]"></textarea>
                    </div>
                </div>

                <div class="mt-6 flex justify-end">
                    <a href="{{ route('services.index') }}" class="bg-gray-100 text-gray-800 px-4 py-2 rounded-lg text-sm font-semibold mr-2">Batal</a>
                    <button type="submit" class="bg-[#00B4D8] hover:bg-[#0096B4] text-white px-4 py-2 rounded-lg text-sm font-semibold">
                        Simpan Layanan
                    </button>
                </div>
            </form>
        </div>
    </div>
</x-app-layout> 