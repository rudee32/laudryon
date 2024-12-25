<x-app-layout>
    <div class="space-y-6">
        <!-- Card Pendapatan -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-white rounded-xl p-6 shadow-sm">
                <div class="flex items-center justify-between">
                    <div>
                        <h3 class="text-sm font-medium text-gray-500">Pendapatan Hari Ini</h3>
                        <p class="text-2xl font-semibold text-gray-700">Rp {{ number_format($todayIncome, 0, ',', '.') }}</p>
                    </div>
                    <div class="bg-[#00B4D8]/10 p-3 rounded-full">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-[#00B4D8]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M12 6v12m-3-2.818l.879.659c1.171.879 3.07.879 4.242 0 1.172-.879 1.172-2.303 0-3.182C13.536 12.219 12.768 12 12 12c-.725 0-1.45-.22-2.003-.659-1.106-.879-1.106-2.303 0-3.182s2.9-.879 4.006 0l.415.33M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                </div>
            </div>

            <div class="bg-white rounded-xl p-6 shadow-sm">
                <div class="flex items-center justify-between">
                    <div>
                        <h3 class="text-sm font-medium text-gray-500">Pendapatan Bulan Ini</h3>
                        <p class="text-2xl font-semibold text-gray-700">Rp {{ number_format($monthIncome, 0, ',', '.') }}</p>
                    </div>
                    <div class="bg-[#00B4D8]/10 p-3 rounded-full">
                        <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-[#00B4D8]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z" />
                        </svg>
                    </div>
                </div>
            </div>
        </div>

        <!-- Filter dan Tabel -->
        <div class="bg-white rounded-xl shadow-sm">
            <div class="p-6 border-b border-gray-100">
                <form action="{{ route('reports.export') }}" method="GET" class="space-y-4">
                    <h2 class="text-lg font-semibold text-gray-800 mb-4">Filter Laporan</h2>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Tanggal Mulai</label>
                            <input type="date" name="tanggal_mulai" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring focus:ring-[#00B4D8]/20" required>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Tanggal Akhir</label>
                            <input type="date" name="tanggal_akhir" class="w-full rounded-lg border-gray-300 focus:border-[#00B4D8] focus:ring focus:ring-[#00B4D8]/20" required>
                        </div>
                        <div class="flex items-end space-x-2">
                            <button type="submit" class="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600">
                                Export Excel
                            </button>
                        </div>
                    </div>
                </form>
            </div>

            <div class="p-6">
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead>
                            <tr class="text-left bg-gray-50">
                                <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">Tanggal</th>
                                <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">No Order</th>
                                <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">Pelanggan</th>
                                <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">Layanan</th>
                                <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">Total</th>
                                <th class="px-6 py-3 text-xs font-medium text-gray-500 uppercase">Status</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100">
                            @foreach($orders as $order)
                            <tr>
                                <td class="px-6 py-4 whitespace-nowrap text-sm">{{ $order->created_at->format('d/m/Y') }}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm">{{ $order->order_number }}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm">{{ $order->customer->name }}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm">{{ $order->service->name }}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm">Rp {{ number_format($order->total_price, 0, ',', '.') }}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $order->status_color }}">
                                        {{ $order->status }}
                                    </span>
                                </td>
                            </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</x-app-layout> 