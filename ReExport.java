// Ghidra headless post-script: export decompiled C + metadata for CTF triage.
// Usage: analyzeHeadless <proj> <name> -import <bin> -scriptPath <dir> \
//          -postScript ReExport.java <outdir> -deleteProject
//@category CTF

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class ReExport extends GhidraScript {

    private static String jstr(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String safe(String s) {
        return s.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ReExport: missing output directory argument");
            return;
        }
        File outDir = new File(args[0]);
        File fnDir = new File(outDir, "decompiled");
        if (!fnDir.exists() && !fnDir.mkdirs()) {
            println("ReExport: cannot create " + fnDir);
            return;
        }

        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(false);
        if (!ifc.openProgram(currentProgram)) {
            println("ReExport: decompiler unavailable: " + ifc.getLastMessage());
        }

        StringBuilder meta = new StringBuilder();
        StringBuilder combined = new StringBuilder();
        meta.append("{\"program\":\"").append(jstr(currentProgram.getName()))
            .append("\",\"language\":\"").append(jstr(currentProgram.getLanguageID().toString()))
            .append("\",\"imageBase\":\"").append(currentProgram.getImageBase())
            .append("\",\"functions\":[");

        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (fit.hasNext() && !monitor.isCancelled()) {
            Function f = fit.next();
            String c = "";
            if (ifc != null) {
                try {
                    DecompileResults res = ifc.decompileFunction(f, 120, monitor);
                    if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                        c = res.getDecompiledFunction().getC();
                    }
                } catch (Exception e) {
                    c = "/* decompile error: " + jstr(e.getMessage()) + " */\n";
                }
            }
            List<String> calls = new ArrayList<>();
            for (Function cf : f.getCalledFunctions(monitor)) {
                calls.add(cf.getName());
            }
            String callsJson = "";
            for (int i = 0; i < Math.min(calls.size(), 40); i++) {
                callsJson += (i > 0 ? "," : "") + "\"" + jstr(calls.get(i)) + "\"";
            }
            if (count > 0) meta.append(",");
            meta.append("{\"name\":\"").append(jstr(f.getName()))
                .append("\",\"addr\":\"").append(f.getEntryPoint())
                .append("\",\"size\":").append(f.getBody().getNumAddresses())
                .append(",\"calls\":[").append(callsJson).append("]}");
            count++;

            String fname = f.getEntryPoint() + "_" + safe(f.getName()) + ".c";
            Writer w = new OutputStreamWriter(
                new FileOutputStream(new File(fnDir, fname)), StandardCharsets.UTF_8);
            w.write("// " + f.getName() + " @ " + f.getEntryPoint()
                    + "  (Ghidra decompiler output; reference only)\n");
            w.write(c == null ? "" : c);
            w.close();

            combined.append("/* ---- ").append(f.getName()).append(" @ ")
                    .append(f.getEntryPoint()).append(" ---- */\n")
                    .append(c == null ? "" : c).append("\n\n");
        }
        meta.append("]");

        // defined strings
        meta.append(",\"strings\":[");
        int sCount = 0;
        DataIterator dit = currentProgram.getListing().getDefinedData(true);
        while (dit.hasNext() && !monitor.isCancelled() && sCount < 200000) {
            Data d = dit.next();
            Object v = d.getValue();
            if (v instanceof String) {
                DataType dt = d.getDataType();
                String t = (String) v;
                if (t.length() >= 4) {
                    if (sCount > 0) meta.append(",");
                    meta.append("{\"addr\":\"").append(d.getAddress())
                        .append("\",\"type\":\"").append(jstr(dt.getName()))
                        .append("\",\"value\":\"").append(jstr(t)).append("\"}");
                    sCount++;
                }
            }
        }
        meta.append("]");

        // external symbols / imports
        meta.append(",\"imports\":[");
        SymbolIterator sit = currentProgram.getSymbolTable().getExternalSymbols();
        int iCount = 0;
        while (sit.hasNext() && !monitor.isCancelled()) {
            Symbol s = sit.next();
            if (iCount > 0) meta.append(",");
            meta.append("\"").append(jstr(s.getName())).append("\"");
            iCount++;
        }
        meta.append("]}");

        Writer mw = new OutputStreamWriter(
            new FileOutputStream(new File(outDir, "meta.json")), StandardCharsets.UTF_8);
        mw.write(meta.toString());
        mw.close();

        Writer cw = new OutputStreamWriter(
            new FileOutputStream(new File(outDir, "pseudocode.c")), StandardCharsets.UTF_8);
        cw.write("/* Ghidra decompiler output for " + currentProgram.getName()
                 + " -- reference only, NOT compilable source */\n\n");
        cw.write(combined.toString());
        cw.close();

        ifc.dispose();
        println("ReExport: wrote " + count + " functions, " + sCount + " strings");
    }
}
