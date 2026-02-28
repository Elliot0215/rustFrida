// Java.use() API — Frida-compatible syntax for Java method hooking
// Evaluated at engine init after C-level Java.hook/unhook/_methods/_getFieldAuto are registered.
(function() {
    "use strict";
    var _hook = Java.hook;
    var _unhook = Java.unhook;
    var _methods = Java._methods;
    var _getFieldAuto = Java._getFieldAuto;
    delete Java.hook;
    delete Java.unhook;
    delete Java._methods;
    delete Java._getFieldAuto;

    // Wrap a raw Java object pointer as a Proxy for field access via dot notation.
    // e.g. ctx.thisObj.mTitle reads the mTitle field via JNI reflection.
    function _wrapJavaObj(ptr, cls) {
        return new Proxy({__jptr: ptr, __jclass: cls}, {
            get: function(target, prop) {
                if (prop === "__jptr") return target.__jptr;
                if (prop === "__jclass") return target.__jclass;
                if (typeof prop !== "string") return undefined;
                if (prop === "toString") return function() {
                    return "[JavaObject:" + target.__jclass + "]";
                };
                if (prop === "valueOf") return function() {
                    return "[JavaObject:" + target.__jclass + "]";
                };
                var result = _getFieldAuto(target.__jptr, target.__jclass, prop);
                // Object fields come back as {__jptr, __jclass} — wrap recursively
                if (result !== null && typeof result === "object"
                    && result.__jptr !== undefined) {
                    return _wrapJavaObj(result.__jptr, result.__jclass);
                }
                return result;
            }
        });
    }

    function MethodWrapper(cls, method, sig, cache) {
        this._c = cls;
        this._m = method;
        this._s = sig || null;
        this._cache = cache || null;
    }

    // Convert Java type name to JNI type descriptor (mirrors Rust java_type_to_jni)
    function _jniType(t) {
        switch(t) {
            case "void": case "V": return "V";
            case "boolean": case "Z": return "Z";
            case "byte": case "B": return "B";
            case "char": case "C": return "C";
            case "short": case "S": return "S";
            case "int": case "I": return "I";
            case "long": case "J": return "J";
            case "float": case "F": return "F";
            case "double": case "D": return "D";
            default:
                if (t.charAt(0) === '[') return t.replace(/\./g, "/");
                return "L" + t.replace(/\./g, "/") + ";";
        }
    }

    // Frida-compatible overload: accepts Java type names as arguments
    // e.g. .overload("java.lang.String", "int") → matches JNI sig "(Ljava/lang/String;I)..."
    // Also accepts raw JNI signature: .overload("(Ljava/lang/String;)I")
    MethodWrapper.prototype.overload = function() {
        if (arguments.length === 1 && typeof arguments[0] === "string"
            && arguments[0].charAt(0) === '(') {
            // Raw JNI signature passed directly
            return new MethodWrapper(this._c, this._m, arguments[0], this._cache);
        }
        // Build JNI parameter prefix from Java type names
        var paramSig = "(";
        for (var i = 0; i < arguments.length; i++) {
            paramSig += _jniType(arguments[i]);
        }
        paramSig += ")";
        // Find matching method from _methods
        var ms;
        if (this._cache && this._cache.methods) {
            ms = this._cache.methods;
        } else {
            ms = _methods(this._c);
            if (this._cache) this._cache.methods = ms;
        }
        var name = this._m === "$init" ? "<init>" : this._m;
        for (var i = 0; i < ms.length; i++) {
            if (ms[i].name === name && ms[i].sig.indexOf(paramSig) === 0) {
                return new MethodWrapper(this._c, this._m, ms[i].sig, this._cache);
            }
        }
        throw new Error("No matching overload: " + this._c + "." + this._m + paramSig);
    };

    Object.defineProperty(MethodWrapper.prototype, "impl", {
        get: function() { return this._fn || null; },
        set: function(fn) {
            var sig = this._s;
            var name = this._m === "$init" ? "<init>" : this._m;
            if (!sig) {
                var ms;
                if (this._cache && this._cache.methods) {
                    ms = this._cache.methods;
                } else {
                    ms = _methods(this._c);
                    if (this._cache) this._cache.methods = ms;
                }
                var match = [];
                for (var i = 0; i < ms.length; i++) {
                    if (ms[i].name === name) match.push(ms[i]);
                }
                if (match.length === 0)
                    throw new Error("Method not found: " + this._c + "." + this._m);
                if (match.length > 1) {
                    var s = match.map(function(m) { return m.sig; }).join(", ");
                    throw new Error(this._m + " has " + match.length +
                        " overloads, use .overload(sig): " + s);
                }
                sig = match[0].sig;
            }
            if (fn === null || fn === undefined) {
                _unhook(this._c, name, sig);
                this._fn = null;
            } else {
                var cls = this._c;
                var userFn = fn;
                _hook(this._c, name, sig, function(ctx) {
                    if (ctx.thisObj !== undefined) {
                        ctx.thisObj = _wrapJavaObj(ctx.thisObj, cls);
                    }
                    // Wrap object args that have __jptr/__jclass as Proxy objects
                    if (ctx.args) {
                        for (var i = 0; i < ctx.args.length; i++) {
                            var a = ctx.args[i];
                            if (a !== null && typeof a === "object"
                                && a.__jptr !== undefined) {
                                ctx.args[i] = _wrapJavaObj(a.__jptr, a.__jclass);
                            }
                        }
                    }
                    return userFn(ctx);
                });
                this._fn = fn;
            }
        }
    });

    Java.use = function(cls) {
        var cache = {};
        var wrappers = {};
        return new Proxy({}, {
            get: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                if (!wrappers[prop]) wrappers[prop] = new MethodWrapper(cls, prop, null, cache);
                return wrappers[prop];
            }
        });
    };
})();
