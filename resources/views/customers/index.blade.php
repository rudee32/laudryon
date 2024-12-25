<x-app-layout>
    <div class="bg-white rounded-xl shadow-sm">
        <div class="p-6 border-b border-gray-100">
            <div class="flex justify-between items-center">
                <h2 class="text-lg font-semibold text-gray-800">Daftar Pelanggan</h2>
                <a href="{{ route('customers.create') }}" class="bg-[#00B4D8] hover:bg-[#0096B4] text-white px-4 py-2 rounded-lg text-sm font-semibold">
                    Tambah Pelanggan
                </a>
            </div>
        </div>
        
        <div class="p-6">
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead>
                        <tr class="text-left bg-gray-50">
                            <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">Nama</th>
                            <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">No. Telepon</th>
                            <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">Alamat</th>
                            <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">Total Pesanan</th>
                            <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">Aksi</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-100">
                        @foreach($customers as $customer)
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm">{{ $customer->name }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm">{{ $customer->phone }}</td>
                            <td class="px-6 py-4 text-sm">{{ $customer->address }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm">{{ $customer->orders_count }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm space-x-2">
                                <a href="{{ route('customers.edit', $customer) }}" class="text-blue-600 hover:text-blue-900">Edit</a>
                                <form action="{{ route('customers.destroy', $customer) }}" method="POST" class="inline">
                                    @csrf
                                    @method('DELETE')
                                    <button type="submit" class="text-red-600 hover:text-red-900 ml-2" onclick="return confirm('Yakin ingin menghapus?')">Hapus</button>
                                </form>
                            </td>
                        </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</x-app-layout> 