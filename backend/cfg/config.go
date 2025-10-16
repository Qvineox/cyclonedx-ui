package cfg

import (
	"log/slog"
	"strings"
)

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type AppConfig struct {
	LogLevel int `yaml:"log_level" env:"LOG_LEVEL" envDefault:"0"`

	Server ServerConfig `yaml:"server" env-prefix:"SRV_"`

	CycloneDX CyclonedxConfig `yaml:"cyclonedx" env-prefix:"CDX_"`
	//Database DatabaseConfig `yaml:"database" env-prefix:"DB_"`
}

type ServerConfig struct {
	HTTP HTTPConfig `yaml:"http" env-prefix:"HTTP_"`
	GRPC GRPCConfig `yaml:"grpc" env-prefix:"GRPC_"`

	Health bool `yaml:"health" env:"HEALTH" env-default:"true"`

	CorsDebug bool     `yaml:"cors_debug" env:"CORS_DEBUG" env-default:"false"`
	Origins   []string `yaml:"origins" env:"ORIGINS" env-separator:";" env-default:"*"`

	MaxMessageSize uint64 `yaml:"max_message_size" env:"MAX_MSG_SIZE" env-default:"104857600"`
}

type HTTPConfig struct {
	Enable  bool `yaml:"enable" env:"ENABLE" envDefault:"true"`
	Web     bool `yaml:"web" env:"WEB" envDefault:"false"`
	Swagger bool `yaml:"swagger" env:"SWAGGER" envDefault:"false"`

	Host string `yaml:"host" env:"HOST" env-default:"0.0.0.0"`
	Port uint64 `yaml:"port" env:"PORT" env-default:"8080"`
}

type CyclonedxConfig struct {
	MinTransitiveSeverity *float64 `yaml:"min_transitive_severity" env:"MIN_TRANSITIVE_SEVERITY" envDefault:"8.0"`
}

type GRPCConfig struct {
	Enable bool `yaml:"enable" env:"ENABLE" envDefault:"false"`

	Host string `yaml:"host" env:"HOST" env-default:"0.0.0.0"`
	Port uint64 `yaml:"port" env:"PORT" env-default:"8081"`

	Reflect bool `yaml:"reflect" env:"REFLECT" env-default:"false"`
}

//type DatabaseConfig struct {
//	File string `yaml:"bolt_file" env:"BOLT_FILE" env-default:"bolt.db"`
//
//	Host string `yaml:"host" env:"HOST" env-default:"0.0.0.0"`
//	Port uint64 `yaml:"port" env:"PORT" env-default:"8080"`
//
//	User     string `yaml:"user" env:"USER"`
//	Pass     string `yaml:"pass" env:"PASS"`
//	Database string `yaml:"name" env:"NAME" env-default:"pkg_sec_gate"`
//
//	Timezone string `yaml:"timezone" env:"TZ" env-default:"Europe/Moscow"`
//}

func NewAppConfigFromFile(path *string) *AppConfig {
	slog.Info("reading config from file")
	config := AppConfig{}

	err := cleanenv.ReadConfig(*path, &config)
	if err != nil {
		panic("unable to read config: " + err.Error())
	} else {
		slog.Info("config loaded from environment")
	}

	return &config
}

func NewAppConfigFromEnv() *AppConfig {
	slog.Info("reading config from environment")
	config := AppConfig{}

	err := cleanenv.ReadEnv(&config)
	if err != nil {
		panic("unable to read config: " + err.Error())
	} else {
		slog.Info("config loaded from environment",
			slog.Uint64("log level", uint64(config.LogLevel)),
			slog.Group("servers config",
				slog.Bool("health server enabled", config.Server.Health),
				slog.Uint64("max message size", config.Server.MaxMessageSize),
				slog.Group("cors",
					slog.Bool("cors debug enabled", config.Server.CorsDebug),
					slog.String("cors origins", strings.Join(config.Server.Origins, "; ")),
				),
				slog.Group("http server config",
					slog.Bool("enabled", config.Server.HTTP.Enable),
					slog.Bool("ui enabled", config.Server.HTTP.Web),
					slog.Bool("swagger enabled", config.Server.HTTP.Swagger),
					slog.String("host", config.Server.HTTP.Host),
					slog.Uint64("port", config.Server.HTTP.Port),
				),
				slog.Group("grpc server config",
					slog.Bool("enabled", config.Server.GRPC.Enable),
					slog.String("host", config.Server.GRPC.Host),
					slog.Uint64("port", config.Server.GRPC.Port),
					slog.Bool("server reflection", config.Server.GRPC.Reflect),
				),
				slog.Group("cyclonedx analysis config",
					slog.Float64("min transitive severity", *config.CycloneDX.MinTransitiveSeverity),
				)),
		)
	}

	return &config
}
