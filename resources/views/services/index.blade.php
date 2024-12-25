<x-app-layout>
    <div class="bg-white rounded-xl shadow-sm">
        <div class="p-6 border-b border-gray-100">
            <div class="flex justify-between items-center">
                <h2 class="text-lg font-semibold text-gray-800">Daftar Layanan</h2>
                <a href="{{ route('services.create') }}" class="bg-[#00B4D8] hover:bg-[#0096B4] text-white px-4 py-2 rounded-lg text-sm font-semibold">
                    Tambah Layanan
                </a>
            </div>
        </div>
        
        <div class="p-6">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                @foreach($services as $service)
                <div class="bg-white border rounded-xl overflow-hidden">
                    <div class="p-6">
                        <h3 class="text-lg font-semibold text-gray-800">{{ $service->name }}</h3>
                        <p class="text-2xl font-bold text-[#00B4D8] mt-2">
                            Rp {{ number_format($service->price_per_kg) }}/kg
                        </p>
                        <p class="text-sm text-gray-600 mt-2">{{ $service->description }}</p>
                        <div class="mt-4 flex items-center text-sm text-gray-500">
                            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            Estimasi {{ $service->estimated_days }} hari
                        </div>
                        <div class="mt-6 flex space-x-3">
                            <a href="{{ route('services.edit', $service) }}" class="text-blue-600 hover:text-blue-900">Edit</a>
                            <form action="{{ route('services.destroy', $service) }}" method="POST" class="inline">
                                @csrf
                                @method('DELETE')
                                <button type="submit" class="text-red-600 hover:text-red-900" onclick="return confirm('Yakin ingin menghapus?')">Hapus</button>
                            </form>
                        </div>
                    </div>
                </div>
                @endforeach
            </div>
        </div>
    </div>
</x-app-layout> 