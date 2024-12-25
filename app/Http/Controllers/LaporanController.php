<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\Request;
use Maatwebsite\Excel\Facades\Excel;
use App\Exports\TransactionExport;
use Carbon\Carbon;

class LaporanController extends Controller
{
    public function exportExcel(Request $request)
    {
        $tanggal_mulai = $request->tanggal_mulai;
        $tanggal_akhir = $request->tanggal_akhir;

        return Excel::download(
            new TransactionExport($tanggal_mulai, $tanggal_akhir),
            'laporan-transaksi.xlsx'
        );
    }
} 