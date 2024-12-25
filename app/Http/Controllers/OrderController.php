<?php

namespace App\Http\Controllers;

use App\Models\Order;
use App\Models\Customer;
use App\Models\Service;
use Illuminate\Http\Request;

class OrderController extends Controller
{
    public function index()
    {
        $orders = Order::with(['customer', 'service'])->latest()->get();
        return view('orders.index', compact('orders'));
    }

    public function create()
    {
        $customers = Customer::all();
        $services = Service::all();
        return view('orders.create', compact('customers', 'services'));
    }

    public function store(Request $request)
    {
        $request->validate([
            'customer_id' => 'required|exists:customers,id',
            'service_id' => 'required|exists:services,id',
            'weight' => 'required|numeric|min:0.1',
            'pickup_date' => 'nullable|date',
            'notes' => 'nullable|string'
        ]);

        $service = Service::find($request->service_id);
        $total_price = $request->weight * $service->price_per_kg;

        Order::create([
            'order_number' => 'ORD-' . strtoupper(uniqid()),
            'customer_id' => $request->customer_id,
            'service_id' => $request->service_id,
            'weight' => $request->weight,
            'total_price' => $total_price,
            'status' => 'pending',
            'pickup_date' => $request->pickup_date,
            'notes' => $request->notes
        ]);

        return redirect()->route('orders.index')->with('success', 'Pesanan berhasil dibuat');
    }

    public function edit(Order $order)
    {
        $customers = Customer::all();
        $services = Service::all();
        return view('orders.edit', compact('order', 'customers', 'services'));
    }

    public function update(Request $request, Order $order)
    {
        $request->validate([
            'customer_id' => 'required|exists:customers,id',
            'service_id' => 'required|exists:services,id',
            'weight' => 'required|numeric|min:0.1',
            'status' => 'required|in:pending,process,completed,cancelled',
            'pickup_date' => 'nullable|date',
            'notes' => 'nullable|string'
        ]);

        $service = Service::find($request->service_id);
        $total_price = $request->weight * $service->price_per_kg;

        $order->update([
            'customer_id' => $request->customer_id,
            'service_id' => $request->service_id,
            'weight' => $request->weight,
            'total_price' => $total_price,
            'status' => $request->status,
            'pickup_date' => $request->pickup_date,
            'notes' => $request->notes
        ]);

        return redirect()->route('orders.index')->with('success', 'Pesanan berhasil diupdate');
    }

    public function destroy(Order $order)
    {
        $order->delete();
        return redirect()->route('orders.index')->with('success', 'Pesanan berhasil dihapus');
    }

    public function updateStatus(Request $request, Order $order)
    {
        $request->validate([
            'status' => 'required|in:pending,process,completed,cancelled'
        ]);

        $order->update(['status' => $request->status]);

        if ($request->is('reports*')) {
            return redirect()->route('reports.index')->with('success', 'Status pesanan berhasil diperbarui');
        }

        return redirect()->route('orders.index')->with('success', 'Status pesanan berhasil diperbarui');
    }
}
