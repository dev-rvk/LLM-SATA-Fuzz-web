// XML file declarations
declare module '*.xml' {
    const content: string;
    export default content;
  }
  
  // JSON file declarations
  declare module '*.json' {
    const content: any;
    export default content;
  }
  
  // TXT file declarations
  declare module '*.txt' {
    const content: string;
    export default content;
  }

  declare module '*.js' {
    const content: string;
    export default content;
  }