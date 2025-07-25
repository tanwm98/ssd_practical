import js from "@eslint/js";
import globals from "globals";
import { defineConfig } from "eslint/config";
import securityNode from "eslint-plugin-security-node";

export default defineConfig([
  { 
    files: ["**/*.{js,mjs,cjs}"], 
    plugins: { 
      js,
      "security-node": securityNode
    }, 
    extends: ["js/recommended"] 
  },
  { 
    files: ["**/*.{js,mjs,cjs}"], 
    languageOptions: { 
      globals: {
        ...globals.browser,
        ...globals.node
      }
    },
    rules: {
      ...securityNode.configs.recommended.rules
    }
  },
]);