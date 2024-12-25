<x-app-layout>
    <div class="bg-white rounded-xl shadow-sm">
        <div class="p-6 border-b border-gray-100">
            <h2 class="text-lg font-semibold text-gray-800">Tambah Pesanan Baru</h2>
        </div>
        
        <div class="p-6">
            <form action="{{ route('orders.store') }}" method="POST">
                @csrf
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <!-- Pelanggan -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Pelanggan</label>
                        <select name="customer_id" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]" required>
                            <option value="">Pilih Pelanggan</option>
                            @foreach($customers as $customer)
                                <option value="{{ $customer->id }}">{{ $customer->name }}</option>
                            @endforeach
                        </select>
                    </div>

                    <!-- Layanan -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Layanan</label>
                        <select name="service_id" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]" required>
                            <option value="">Pilih Layanan</option>
                            @foreach($services as $service)
                                <option value="{{ $service->id }}">{{ $service->name }} - Rp {{ number_format($service->price_per_kg) }}/kg</option>
                            @endforeach
                        </select>
                    </div>

                    <!-- Berat -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Berat (Kg)</label>
                        <input type="number" name="weight" step="0.1" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]" required>
                    </div>

                    <!-- Tanggal Pengambilan -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Tanggal Pengambilan</label>
                        <input type="date" name="pickup_date" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]">
                    </div>

                    <!-- Catatan -->
                    <div class="md:col-span-2">
                        <label class="block text-sm font-medium text-gray-700 mb-2">Catatan</label>
                        <textarea name="notes" rows="3" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring-[#00B4D8]"></textarea>
                    </div>
                </div>

                <div class="mt-6 flex justify-end">
                    <a href="{{ route('orders.index') }}" class="bg-gray-100 text-gray-800 px-4 py-2 rounded-lg text-sm font-semibold mr-2">Batal</a>
                    <button type="submit" class="bg-[#00B4D8] hover:bg-[#0096B4] text-white px-4 py-2 rounded-lg text-sm font-semibold">
                        Simpan Pesanan
                    </button>
                </div>
            </form>
        </div>
    </div>
</x-app-layout> 