import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "JWT Demo",
  description: "By Luciano Nooijen",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        {children}
      </body>
    </html>
  );
}
