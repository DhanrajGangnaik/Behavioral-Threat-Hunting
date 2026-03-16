type Props = {
  title: string;
  src: string;
};

export default function EmbeddedGrafana({ title, src }: Props) {
  return (
    <div className="card">
      <h3>{title}</h3>
      <iframe
        src={src}
        title={title}
        style={{ width: "100%", height: "350px", border: "none", borderRadius: "8px" }}
      />
    </div>
  );
}