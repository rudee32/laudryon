<?php

namespace App\Exports;

use App\Models\Order;
use Maatwebsite\Excel\Concerns\FromCollection;
use Maatwebsite\Excel\Concerns\WithHeadings;
use Maatwebsite\Excel\Concerns\WithMapping;
use Carbon\Carbon;

class TransactionExport implements FromCollection, WithHeadings, WithMapping
{
    protected $tanggal_mulai;
    protected $tanggal_akhir;

    public function __construct($tanggal_mulai = null, $tanggal_akhir = null)
    {
        $this->tanggal_mulai = $tanggal_mulai;
        $this->tanggal_akhir = $tanggal_akhir;
    }

    public function collection()
    {
        $query = Order::with(['customer', 'service']);
        
        if ($this->tanggal_mulai && $this->tanggal_akhir) {
            $query->whereBetween('created_at', [
                Carbon::parse($this->tanggal_mulai)->startOfDay(),
                Carbon::parse($this->tanggal_akhir)->endOfDay()
            ]);
        }

        return $query->get();
    }

    public function headings(): array
    {
        return [
            'Tanggal',
            'No Order',
            'Pelanggan',
            'Layanan',
            'Total',
            'Status'
        ];
    }

    public function map($order): array
    {
        return [
            $order->created_at->format('d/m/Y'),
            $order->order_number,
            $order->customer->name,
            $order->service->name,
            'Rp ' . number_format($order->total_price, 0, ',', '.'),
            $order->status
        ];
    }
} 