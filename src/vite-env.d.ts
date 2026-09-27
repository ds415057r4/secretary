declare module "virtual:brand-logos" {
  const logos: {
    width?: number;
    height?: number;
    icons: Record<string, { body: string; width?: number; height?: number }>;
  };
  export default logos;
}
