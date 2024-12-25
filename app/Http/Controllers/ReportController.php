<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\Request;
use Carbon\Carbon;

class ReportController extends Controller
{
    public function index(Request $request)
    {
        $query = Order::with(['customer', 'service']);

        if ($request->filled('start_date') && $request->filled('end_date')) {
            $query->whereBetween('created_at', [
                Carbon::parse($request->start_date)->startOfDay(),
                Carbon::parse($request->end_date)->endOfDay()
            ]);
        }

        $orders = $query->latest()->get();
        
        // Hitung pendapatan hari ini
        $todayIncome = Order::whereDate('created_at', Carbon::today())
            ->where('status', 'completed')
            ->sum('total_price');
            
        // Hitung pendapatan bulan ini
        $monthIncome = Order::whereMonth('created_at', Carbon::now()->month)
            ->whereYear('created_at', Carbon::now()->year)
            ->where('status', 'completed')
            ->sum('total_price');

        return view('reports.index', compact('orders', 'todayIncome', 'monthIncome'));
    }
}
