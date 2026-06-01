declare const _default: {
    content: string[];
    theme: {
        extend: {
            colors: {
                soc: {
                    indigo: string;
                    "indigo-light": string;
                    "cyber-green": string;
                    "cyber-green-glow": string;
                    "alert-rose": string;
                    "critical-amber": string;
                    emerald: string;
                    cyan: string;
                    "cyan-glow": string;
                    "electric-blue": string;
                    "electric-purple": string;
                };
                "deep-dark": {
                    900: string;
                    950: string;
                    975: string;
                };
            };
            backgroundImage: {
                "soc-gradient": string;
                "cyber-gradient": string;
                "amber-gradient": string;
                "emerald-gradient": string;
                "deep-dark-gradient": string;
                "cyber-dark-gradient": string;
            };
            boxShadow: {
                neon: string;
                "soc-glow": string;
                "cyber-glow": string;
                "amber-glow": string;
                "rose-glow": string;
            };
            keyframes: {
                "terminal-fade": {
                    "0%": {
                        opacity: string;
                        transform: string;
                    };
                    "100%": {
                        opacity: string;
                        transform: string;
                    };
                };
                "pulse-glow": {
                    "0%, 100%": {
                        boxShadow: string;
                    };
                    "50%": {
                        boxShadow: string;
                    };
                };
                "cyber-pulse": {
                    "0%, 100%": {
                        boxShadow: string;
                    };
                    "50%": {
                        boxShadow: string;
                    };
                };
                breathing: {
                    "0%, 100%": {
                        opacity: string;
                    };
                    "50%": {
                        opacity: string;
                    };
                };
                "danger-pulse": {
                    "0%, 100%": {
                        opacity: string;
                        boxShadow: string;
                    };
                    "50%": {
                        opacity: string;
                        boxShadow: string;
                    };
                };
            };
            animation: {
                "terminal-fade": string;
                "pulse-glow": string;
                "cyber-pulse": string;
                breathing: string;
                "danger-pulse": string;
            };
        };
    };
    plugins: never[];
};
export default _default;
